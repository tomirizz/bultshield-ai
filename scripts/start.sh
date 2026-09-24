#!/bin/sh
set -eu
python -m app.bootstrap
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}" --no-server-header
