"""Worker-owned scratch space and bounded process execution."""
import fcntl
import os
import shutil
import signal
import subprocess
import time
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from tempfile import TemporaryDirectory

_workspace = ContextVar('scan_workspace', default=None)
_lock_fd = ContextVar('scan_lock_fd', default=None)

def inherited_lock():
    fd = _lock_fd.get()
    return () if fd is None else (fd,)



def timeout_seconds(name, default):
    value = int(os.environ.get(name, default))
    if not 1 <= value <= 1800:
        raise ValueError(f'{name} must be between 1 and 1800 seconds')
    return value


def workspace_root():
    root = Path(os.environ.get('SCAN_WORKSPACE_ROOT', str(Path.home() / '.cache' / 'bultshield-jobs')))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


@contextmanager
def job_workspace(job_id):
    with TemporaryDirectory(prefix=f'{job_id}-', dir=workspace_root()) as directory:
        root = Path(directory)
        with (root / '.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            token = _workspace.set(root)
            lock_token = _lock_fd.set(lock.fileno())
            try:
                yield root
            finally:
                _workspace.reset(token)
                _lock_fd.reset(lock_token)


def temporary_directory(*, prefix, dir=None):
    return TemporaryDirectory(prefix=prefix, dir=_workspace.get() or dir)


def cleanup_orphans(min_age=3600):
    """Remove old unlocked workspaces, never active jobs or the shared CVE cache."""
    for directory in workspace_root().iterdir():
        if directory.is_symlink() or not directory.is_dir():
            continue
        try:
            if time.time() - directory.stat().st_mtime < min_age:
                continue
            lock_path = directory / '.lock'
            if lock_path.is_symlink() or not lock_path.is_file():
                continue
            with lock_path.open('r') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                shutil.rmtree(directory)
        except FileNotFoundError:
            pass


def run_process(command, *, cwd, env, timeout):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=inherited_lock())
    try:
        code = process.wait(timeout=timeout)
    except BaseException:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    return subprocess.CompletedProcess(command, code)
