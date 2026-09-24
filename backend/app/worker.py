import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from uuid import UUID

from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from .config import get_settings
from .finding_normalizer import normalize_gitleaks, normalize_semgrep, normalize_trivy
from .gitleaks_runner import GitleaksError, run_gitleaks
from .models import Repository, Scan, ScanJob, ScanStatus
from .repository_checkout import (
    RepositoryCheckoutError,
    checkout_repository,
)
from .scanner_catalog import RULES_SHA256, SCANNERS, SEMGREP_VERSION, TRIVY_VERSION, scan_configuration
from .semgrep_runner import SemgrepError, run_semgrep
from .trivy_runner import TrivyError, run_trivy


def now():
    return datetime.now(timezone.utc)


@lru_cache
def sessions():
    engine = create_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=0,
        connect_args={
            "connect_timeout": 5,
            "options": "-c statement_timeout=30000 -c lock_timeout=5000",
        },
    )
    return sessionmaker(bind=engine, expire_on_commit=False)


@dataclass(frozen=True)
class JobData:
    job_id: UUID
    scan_id: UUID
    project_id: UUID
    repository_id: UUID
    url: str
    branch: str


class JobNoLongerActive(RuntimeError):
    pass


def mark_failed(db, job, message):
    timestamp = now()
    job.status = "FAILED"
    job.heartbeat_at = timestamp

    scan = db.get(Scan, job.scan_id)
    if scan is not None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message
        scan.completed_at = timestamp
        results = dict(scan.scanner_results or {})
        for scanner in scan.scanner_config.get("scanners", list(SCANNERS)):
            if results.get(scanner, {}).get("status") != "COMPLETED":
                results[scanner] = {"status": "FAILED", "error": message}
        scan.scanner_results = results


def recover_stale_jobs():
    cutoff = now() - timedelta(minutes=15)

    with sessions().begin() as db:
        jobs = db.scalars(
            select(ScanJob)
            .where(
                ScanJob.status == "RUNNING",
                func.coalesce(
                    ScanJob.heartbeat_at,
                    ScanJob.locked_at,
                    ScanJob.created_at,
                ) < cutoff,
            )
            .order_by(ScanJob.created_at)
            .limit(20)
            .with_for_update(skip_locked=True)
        ).all()

        for job in jobs:
            mark_failed(
                db,
                job,
                "Worker перестал отвечать. Запустите новую проверку.",
            )


def claim_job():
    with sessions().begin() as db:
        job = db.scalar(
            select(ScanJob)
            .where(ScanJob.status == "QUEUED")
            .order_by(ScanJob.created_at, ScanJob.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )

        if job is None:
            return None

        scan = db.get(Scan, job.scan_id)
        repository = (
            db.get(Repository, scan.repository_id)
            if scan is not None
            else None
        )

        if scan is None or repository is None:
            mark_failed(db, job, "Репозиторий задания не найден.")
            return None

        timestamp = now()

        job.status = "RUNNING"
        job.attempts += 1
        job.locked_at = timestamp
        job.heartbeat_at = timestamp

        scan.status = ScanStatus.CLONING
        scan.started_at = timestamp
        scan.completed_at = None
        scan.error_message = None
        scan.scanner_config = scan_configuration(repository.default_branch)
        scan.scanner_results = {name: {"status": "PENDING"} for name in SCANNERS}

        return JobData(
            job_id=job.id,
            scan_id=scan.id,
            project_id=scan.project_id,
            repository_id=repository.id,
            url=repository.url,
            branch=repository.default_branch,
        )


def active_records(db, data):
    job = db.scalar(
        select(ScanJob)
        .where(ScanJob.id == data.job_id)
        .with_for_update()
    )

    if job is None or job.status != "RUNNING":
        raise JobNoLongerActive()

    scan = db.get(Scan, data.scan_id)
    if scan is None:
        raise JobNoLongerActive()

    return job, scan


def update_progress(data, status, commit_sha=None):
    with sessions().begin() as db:
        job, scan = active_records(db, data)
        job.heartbeat_at = now()
        scan.status = status

        if commit_sha is not None:
            scan.commit_sha = commit_sha


def fail_job(data, message):
    with sessions().begin() as db:
        job = db.scalar(
            select(ScanJob)
            .where(ScanJob.id == data.job_id)
            .with_for_update()
        )

        if job is not None and job.status == "RUNNING":
            mark_failed(db, job, message)


def execute_job(data):
    print(f"SCAN_STARTED {data.scan_id}", flush=True)
    failures = []
    with checkout_repository(data.url, data.branch) as checkout:
        repository_path, commit_sha = checkout
        update_progress(data, ScanStatus.SCANNING, commit_sha=commit_sha)
        for name, runner, normalizer, expected_error in (
            ("gitleaks", run_gitleaks, normalize_gitleaks, GitleaksError),
            ("semgrep", run_semgrep, normalize_semgrep, SemgrepError),
            ("trivy", run_trivy, normalize_trivy, TrivyError),
        ):
            with sessions().begin() as db:
                job, scan = active_records(db, data)
                job.heartbeat_at = now()
                scan.status = ScanStatus.SCANNING
                scan.scanner_results = {**scan.scanner_results, name: {"status": "RUNNING"}}
            try:
                report = runner(repository_path)
                update_progress(data, ScanStatus.NORMALIZING)
                results = report if name == "gitleaks" else report.findings
                findings = normalizer(results, project_id=data.project_id, repository_id=data.repository_id,
                                      scan_id=data.scan_id, commit_sha=commit_sha)
                summary = {
                    "status": "COMPLETED", "finding_count": len(findings),
                    "version": {"gitleaks": "8.30.1", "semgrep": SEMGREP_VERSION, "trivy": TRIVY_VERSION}[name],
                    "scope": "branch_snapshot", "source_redacted": True,
                }
                if name == "semgrep":
                    summary.update(scanned_files=report.scanned_files, rules_sha256=RULES_SHA256)
                elif name == "trivy":
                    summary.update(report.summary)
                else:
                    summary["secrets_redacted"] = True
                # Each scanner's findings and status commit together. Another scanner's
                # failure or a worker restart cannot erase already completed findings.
                with sessions().begin() as db:
                    job, scan = active_records(db, data)
                    db.add_all(findings)
                    scan.scanner_results = {**scan.scanner_results, name: summary}
                    job.heartbeat_at = now()
            except expected_error as exc:
                message = str(exc)
                failures.append(name)
                with sessions().begin() as db:
                    job, scan = active_records(db, data)
                    scan.scanner_results = {**scan.scanner_results, name: {"status": "FAILED", "error": message}}
                    job.heartbeat_at = now()
    # The temporary repository and unredacted reports are gone before final status.
    with sessions().begin() as db:
        job, scan = active_records(db, data)
        timestamp = now()
        scan.status = ScanStatus.FAILED if failures else ScanStatus.COMPLETED
        scan.error_message = ("Неполная проверка: " + ", ".join(failures) + ". Результаты успешных сканеров сохранены.") if failures else None
        scan.completed_at = timestamp
        job.status = "FAILED" if failures else "COMPLETED"
        job.heartbeat_at = timestamp
    print(f"SCAN_{job.status} {data.scan_id}", flush=True)

def process_job(data):
    try:
        execute_job(data)
    except JobNoLongerActive:
        print(f"SCAN_NO_LONGER_ACTIVE {data.scan_id}", flush=True)
    except (RepositoryCheckoutError, GitleaksError) as exc:
        fail_job(data, str(exc))
        print(f"SCAN_FAILED {data.scan_id}", flush=True)
    except Exception:
        # Не выводим исключение: оно может содержать данные репозитория.
        fail_job(
            data,
            "Внутренняя ошибка обработки. Запустите новую проверку.",
        )
        print(f"SCAN_FAILED {data.scan_id}", flush=True)


def main():
    print("BULTSHIELD_WORKER_STARTING", flush=True)
    database_available = False

    while True:
        try:
            recover_stale_jobs()
            data = claim_job()

            if not database_available:
                print("BULTSHIELD_WORKER_READY", flush=True)
                database_available = True

            if data is None:
                time.sleep(2)
                continue

            process_job(data)

        except SQLAlchemyError:
            database_available = False
            print("WORKER_DATABASE_UNAVAILABLE", flush=True)
            time.sleep(5)
        except KeyboardInterrupt:
            print("BULTSHIELD_WORKER_STOPPED", flush=True)
            break


if __name__ == "__main__":
    main()
