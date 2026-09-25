import json
import os
import shutil
import subprocess
from pathlib import Path

from .scan_runtime import run_process, temporary_directory, timeout_seconds


class GitleaksError(RuntimeError):
    """Сообщение об ошибке без содержимого секретов."""


def _check_size(repository: Path) -> None:
    total_size = 0

    for directory, folders, files in os.walk(repository):
        folders[:] = [
            name
            for name in folders
            if name != ".git"
            and not (Path(directory) / name).is_symlink()
        ]

        for name in files:
            path = Path(directory) / name

            if path.is_symlink():
                continue

            size = path.stat().st_size
            total_size += size

            if size > 2 * 1024 * 1024:
                raise GitleaksError(
                    "Файл превышает лимит MVP: 2 МБ. "
                    "Сканирование не выполнено."
                )

            if total_size > 50 * 1024 * 1024:
                raise GitleaksError(
                    "Размер файлов превышает лимит MVP: 50 МБ. "
                    "Сканирование не выполнено."
                )


def _sanitize_finding(item: dict, repository: Path) -> dict:
    rule_id = item.get("RuleID")
    description = item.get("Description")
    filename = item.get("File")

    if not all(
        isinstance(value, str) and value
        for value in (rule_id, description, filename)
    ):
        raise GitleaksError("Некорректная запись в отчёте Gitleaks.")

    if len(rule_id) > 300:
        raise GitleaksError("Некорректный идентификатор правила.")

    # Проверяем, что находка относится к файлу внутри репозитория.
    path = Path(filename)
    if not path.is_absolute():
        path = repository / path

    try:
        relative = path.resolve().relative_to(repository).as_posix()
    except ValueError:
        raise GitleaksError(
            "Gitleaks вернул путь вне репозитория."
        ) from None

    if len(relative) > 2048:
        raise GitleaksError("Слишком длинный путь в отчёте.")

    positions = {}
    for field in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
        value = item.get(field, 0)
        if type(value) is not int or value < 0:
            raise GitleaksError("Некорректная позиция находки.")
        positions[field] = value

    # Возвращаем только разрешённые поля.
    # Исходные Match, Secret и Fragment дальше не передаются.
    return {
        "RuleID": rule_id,
        "Description": description[:300],
        "File": relative,
        **positions,
        "Match": "[REDACTED]",
        "Secret": "[REDACTED]",
    }


def run_gitleaks(repository: Path) -> list[dict]:
    repository = repository.resolve()

    if not repository.is_dir():
        raise GitleaksError("Папка репозитория не найдена.")

    executable = shutil.which("gitleaks")
    if executable is None:
        raise GitleaksError("Gitleaks не установлен в worker.")

    try:
        _check_size(repository)

        with temporary_directory(prefix="bultshield-report-") as temporary:
            workspace = Path(temporary)
            report = workspace / "report.json"
            config = workspace / "trusted.toml"
            ignore = workspace / ".gitleaksignore"

            # Используем стандартные правила Gitleaks.
            # Настройки из проверяемого репозитория не загружаем.
            config.write_text(
                "[extend]\nuseDefault = true\n",
                encoding="utf-8",
            )
            ignore.write_text("", encoding="utf-8")

            command = [
                executable,
                "dir",
                str(repository),
                "--config", str(config),
                "--gitleaks-ignore-path", str(ignore),
                "--ignore-gitleaks-allow",
                "--report-format", "json",
                "--report-path", str(report),
                "--redact=100",
                "--exit-code", "10",
                "--max-archive-depth", "0",
                "--max-decode-depth", "0",
                "--no-banner",
                "--no-color",
                "--log-level", "error",
            ]

            environment = {
                "PATH": os.defpath,
                "HOME": str(workspace),
                "LANG": "C.UTF-8",
                "GOMEMLIMIT": "256MiB",
            }

            result = run_process(
                command,
                cwd=repository,
                env=environment,
                timeout=timeout_seconds("GITLEAKS_TIMEOUT_SECONDS", 180),
            )

            # 10 означает найденные секреты, а не сбой сканера.
            if result.returncode not in (0, 10):
                raise GitleaksError(
                    f"Gitleaks завершился с ошибкой: {result.returncode}."
                )

            if not report.is_file():
                raise GitleaksError("Gitleaks не создал JSON-отчёт.")

            if report.stat().st_size > 10 * 1024 * 1024:
                raise GitleaksError("Отчёт превышает лимит MVP: 10 МБ.")

            data = json.loads(report.read_text(encoding="utf-8"))
            if data is None:
                data = []

            if not isinstance(data, list):
                raise GitleaksError("Некорректный формат JSON-отчёта.")

            if (result.returncode == 10) != bool(data):
                raise GitleaksError(
                    "Код завершения не совпадает с содержимым отчёта."
                )

            findings = []
            for item in data:
                if not isinstance(item, dict):
                    raise GitleaksError("Некорректная запись отчёта.")
                findings.append(_sanitize_finding(item, repository))

            return findings

    except subprocess.TimeoutExpired:
        raise GitleaksError(
            "Gitleaks превысил лимит времени."
        ) from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise GitleaksError(
            "Не удалось прочитать файлы или отчёт Gitleaks."
        ) from None
