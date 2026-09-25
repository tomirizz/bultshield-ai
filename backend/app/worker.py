import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from uuid import UUID, uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from .config import get_settings
from .models import Repository, Scan, ScanJob, ScanStatus
from .repository_checkout import RepositoryCheckoutError
from .scan_engine import log_event, run_pipeline
from .scan_runtime import cleanup_orphans
from .scanner_catalog import SCANNERS, scan_configuration
from .trivy_runner import log_trivy_storage

WORKER_ID = str(uuid4())
HEARTBEAT_SECONDS = 15
STALE_SECONDS = 180


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


def mark_failed(db, job, message, code="WORKER_FAILED"):
    timestamp = now()
    job.status = "FAILED"
    job.heartbeat_at = timestamp

    scan = db.get(Scan, job.scan_id)
    if scan is not None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message
        scan.error_code = code
        scan.completed_at = timestamp
        results = dict(scan.scanner_results or {})
        for scanner in scan.scanner_config.get("scanners", list(SCANNERS)):
            if results.get(scanner, {}).get("status") != "COMPLETED":
                results[scanner] = {**results.get(scanner, {}), "status": "FAILED", "error": message, "error_code": code}
        scan.scanner_results = results


def recover_stale_jobs():
    cutoff = now() - timedelta(seconds=STALE_SECONDS)

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
                code="WORKER_LOST",
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
        job.worker_id = WORKER_ID
        job.attempts += 1
        job.locked_at = timestamp
        job.heartbeat_at = timestamp

        scan.status = ScanStatus.CLONING
        scan.current_step = "clone"
        scan.error_code = None
        scan.started_at = timestamp
        scan.completed_at = None
        scan.error_message = None
        scan.scanner_config = scan_configuration(scan.scanner_config.get("branch", repository.default_branch))
        scan.scanner_results = {name: {"status": "PENDING"} for name in SCANNERS}

        return JobData(
            job_id=job.id,
            scan_id=scan.id,
            project_id=scan.project_id,
            repository_id=repository.id,
            url=repository.url,
            branch=scan.scanner_config["branch"],
        )


def active_records(db, data):
    job = db.scalar(
        select(ScanJob)
        .where(ScanJob.id == data.job_id)
        .with_for_update()
    )

    if job is None or job.status != "RUNNING" or job.worker_id != WORKER_ID:
        raise JobNoLongerActive()

    scan = db.get(Scan, data.scan_id)
    if scan is None:
        raise JobNoLongerActive()

    return job, scan


def update_progress(data, status, commit_sha=None, step=None, scanner_result=None):
    with sessions().begin() as db:
        job, scan = active_records(db, data)
        job.heartbeat_at = now()
        scan.status = status
        scan.current_step = step
        if scanner_result:
            name, result = scanner_result
            scan.scanner_results = {**scan.scanner_results, name: result}

        if commit_sha is not None:
            scan.commit_sha = commit_sha


def fail_job(data, message, code="WORKER_FAILED"):
    with sessions().begin() as db:
        job = db.scalar(
            select(ScanJob)
            .where(ScanJob.id == data.job_id)
            .with_for_update()
        )

        if job is not None and job.status == "RUNNING" and job.worker_id == WORKER_ID:
            mark_failed(db, job, message, code)


def store_results(data, findings, summaries):
    with sessions().begin() as db:
        job, scan = active_records(db, data)
        db.add_all(findings)
        failed = [name for name, result in summaries.items() if result["status"] == "FAILED"]
        timestamp = now()
        scan.scanner_results = summaries
        scan.status = ScanStatus.FAILED if failed else ScanStatus.COMPLETED
        scan.error_message = ("Неполная проверка: " + ", ".join(failed) + ". Результаты успешных сканеров сохранены.") if failed else None
        scan.error_code = "SCANNER_FAILED" if failed else None
        scan.current_step = "store" if failed else "completed"
        scan.completed_at = timestamp
        job.status = "FAILED" if failed else "COMPLETED"
        job.heartbeat_at = timestamp


def heartbeat(data):
    with sessions().begin() as db:
        job, _ = active_records(db, data)
        job.heartbeat_at = now()


@contextmanager
def keep_alive(data):
    stop = threading.Event()

    def pulse():
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                heartbeat(data)
            except JobNoLongerActive:
                return
            except SQLAlchemyError:
                log_event(data, "heartbeat_failed", error_code="DATABASE_UNAVAILABLE")

    thread = threading.Thread(target=pulse, daemon=True, name="scan-heartbeat")
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=40)


def execute_job(data):
    # Reject a stale/replayed claim before cloning or starting subprocesses.
    heartbeat(data)
    with keep_alive(data):
        run_pipeline(data, update_progress, store_results)


def process_job(data):
    try:
        execute_job(data)
    except JobNoLongerActive:
        log_event(data, "scan_no_longer_active")
    except RepositoryCheckoutError as exc:
        fail_job(data, str(exc), "CHECKOUT_FAILED")
        log_event(data, "scan_failed", error_code="CHECKOUT_FAILED")
    except Exception:
        fail_job(data, "Внутренняя ошибка обработки. Запустите новую проверку.", "INTERNAL_ERROR")
        log_event(data, "scan_failed", error_code="INTERNAL_ERROR")


def main():
    print("BULTSHIELD_WORKER_STARTING", flush=True)
    log_trivy_storage()
    database_available = False
    next_cleanup = 0

    while True:
        try:
            if time.monotonic() >= next_cleanup:
                try:
                    cleanup_orphans()
                except OSError:
                    print("WORKER_CLEANUP_FAILED", flush=True)
                next_cleanup = time.monotonic() + 60
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
