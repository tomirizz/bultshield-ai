import os
import re
import shutil
import signal
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from pydantic import ValidationError

from .scan_runtime import inherited_lock, limited_command, temporary_directory, timeout_seconds
from .schemas import RepositoryCreate


class RepositoryCheckoutError(RuntimeError):
    """Безопасное сообщение об ошибке для пользователя."""


def _run_git(
    git: str,
    arguments: list[str],
    directory: Path,
    environment: dict[str, str],
    timeout: int,
    capture: bool = False,
) -> str:
    command = [
        git,
        "-c", "credential.helper=",
        "-c", "http.followRedirects=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.symlinks=false",
        *arguments,
    ]

    try:
        process = subprocess.Popen(
            limited_command(command, timeout),
            cwd=directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True, pass_fds=inherited_lock(),
        )
    except OSError:
        raise RepositoryCheckoutError(
            "Не удалось запустить Git."
        ) from None

    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RepositoryCheckoutError(
            "Превышено время загрузки репозитория."
        ) from None

    if process.returncode != 0:
        raise RepositoryCheckoutError(
            "Не удалось загрузить репозиторий. "
            "Проверьте публичный GitHub URL и название ветки."
        )

    return (output or "").strip()


@contextmanager
def checkout_repository(
    url: str,
    branch: str = "main",
    commit: str | None = None,
) -> Iterator[tuple[Path, str]]:
    try:
        repository = RepositoryCreate(
            url=url,
            default_branch=branch,
        )
    except ValidationError:
        raise RepositoryCheckoutError(
            "Некорректный GitHub URL или название ветки."
        ) from None

    git = shutil.which("git")
    if git is None:
        raise RepositoryCheckoutError(
            "Git не установлен в сервисе сканирования."
        )

    with temporary_directory(prefix="bultshield-scan-") as temporary:
        workspace = Path(temporary)
        destination = workspace / "repository"

        # Git не получает DATABASE_URL и другие секреты worker.
        environment = {
            "PATH": os.defpath,
            "HOME": str(workspace),
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }

        if commit:
            if not re.fullmatch(r'[0-9a-f]{40}', commit):
                raise RepositoryCheckoutError('Некорректный исходный commit.')
            destination.mkdir()
            for args in (['init'], ['remote', 'add', 'origin', repository.url],
                         ['fetch', '--depth', '1', '--no-tags', 'origin', commit],
                         ['checkout', '--detach', 'FETCH_HEAD']):
                _run_git(git, args, destination, environment, timeout_seconds('CLONE_TIMEOUT_SECONDS', 120))
        else:
            _run_git(
                git,
                [
                    "clone",
                    "--depth", "1",
                    "--single-branch",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--branch", repository.default_branch,
                    "--",
                    repository.url,
                    str(destination),
                ],
                workspace,
                environment,
                timeout=timeout_seconds("CLONE_TIMEOUT_SECONDS", 120),
            )

        commit_sha = _run_git(
            git,
            ["rev-parse", "--verify", "HEAD"],
            destination,
            environment,
            timeout=10,
            capture=True,
        )

        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha):
            raise RepositoryCheckoutError(
                "Не удалось определить commit репозитория."
            )

        if commit and commit_sha != commit:
            raise RepositoryCheckoutError('Commit исходной проверки недоступен.')
        yield destination, commit_sha
