"""Run integration tests only against the local disposable database from .env."""

import os
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

root = Path(__file__).resolve().parents[1]
values = dotenv_values(root / ".env")
database_url = os.environ.get("TEST_DATABASE_URL") or values.get("DATABASE_URL")
if not database_url:
    raise SystemExit("Set TEST_DATABASE_URL to a local PostgreSQL database ending with _test.")
result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pytest",
        "-c",
        "backend/pyproject.toml",
        "backend/tests",
        "-q",
    ],
    cwd=root,
    check=False,
    env={**os.environ, "DATABASE_URL": database_url, "TEST_DATABASE_URL": database_url},
)
raise SystemExit(result.returncode)
