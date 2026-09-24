FROM node:24-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 APP_ENV=production FRONTEND_DIST=/app/frontend/dist
WORKDIR /app/backend
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 bultshield
COPY --chown=bultshield:bultshield backend/ ./
COPY --from=frontend --chown=bultshield:bultshield /build/dist /app/frontend/dist
COPY --chown=bultshield:bultshield scripts/start.sh /app/start.sh
USER bultshield
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=90s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=5)"
CMD ["sh", "/app/start.sh"]
