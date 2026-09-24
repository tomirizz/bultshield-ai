import os
import re
import shutil
import signal
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import ValidationError

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
            command,
            cwd=directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
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

    with TemporaryDirectory(prefix="bultshield-scan-") as temporary:
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
            timeout=90,
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

        yield destination, commit_sha
