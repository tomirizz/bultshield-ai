import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from uuid import UUID

from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from .config import get_settings
from .finding_normalizer import normalize_gitleaks
from .gitleaks_runner import GitleaksError, run_gitleaks
from .models import Repository, Scan, ScanJob, ScanStatus
from .repository_checkout import (
    RepositoryCheckoutError,
    checkout_repository,
)


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
        scan.scanner_results = {
            "gitleaks": {
                "status": "FAILED",
                "error": message,
            }
        }


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
        scan.scanner_config = {
            "scanners": ["gitleaks"],
            "scope": "branch_snapshot",
            "branch": repository.default_branch,
            "gitleaks_version": "8.30.1",
            "max_file_bytes": 2 * 1024 * 1024,
            "max_total_bytes": 50 * 1024 * 1024,
            "archive_depth": 0,
            "decode_depth": 0,
        }

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

    with checkout_repository(data.url, data.branch) as checkout:
        repository_path, commit_sha = checkout

        update_progress(
            data,
            ScanStatus.SCANNING,
            commit_sha=commit_sha,
        )

        results = run_gitleaks(repository_path)

    # К этому моменту временная копия репозитория удалена.
    update_progress(data, ScanStatus.NORMALIZING)

    findings = normalize_gitleaks(
        results,
        project_id=data.project_id,
        repository_id=data.repository_id,
        scan_id=data.scan_id,
        commit_sha=commit_sha,
    )

    # Findings и итоговые статусы сохраняются одной транзакцией.
    with sessions().begin() as db:
        job, scan = active_records(db, data)
        db.add_all(findings)

        timestamp = now()

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = timestamp
        scan.error_message = None
        scan.scanner_results = {
            "gitleaks": {
                "status": "COMPLETED",
                "finding_count": len(findings),
                "version": "8.30.1",
                "scope": "branch_snapshot",
                "secrets_redacted": True,
            }
        }

        job.status = "COMPLETED"
        job.heartbeat_at = timestamp

    print(
        f"SCAN_COMPLETED {data.scan_id} findings={len(findings)}",
        flush=True,
    )


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
