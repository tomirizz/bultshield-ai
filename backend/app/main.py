from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .ai_service import router as ai_router
from .ai_service import start_service
from .api import router
from .config import get_settings
from .database import get_engine
from .security_dashboard import router as dashboard_router


@asynccontextmanager
async def lifespan(app):
    stop = start_service() if get_settings().ai_enabled else None
    yield
    if stop:
        stop.set()


def create_app() -> FastAPI:
    app = FastAPI(title="BultShield", version="0.8.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.include_router(router)
    app.include_router(dashboard_router)
    app.include_router(ai_router)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return JSONResponse(status_code=503, content={"detail": "База данных временно недоступна. Повторите запрос позже."})

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        )
        if request.url.path.startswith(("/api/", "/health/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health/live")
    def liveness():
        return {"status": "ok", "app": "bultshield-ai", "stage": 8}

    @app.get("/health/ready")
    def readiness():
        try:
            with get_engine().connect() as connection:
                revision = connection.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
                connection.execute(text("SELECT id FROM projects LIMIT 1"))
            if not revision:
                raise HTTPException(503, "Миграции ещё не выполнены")
        except SQLAlchemyError:
            return JSONResponse(status_code=503, content={"status": "unavailable", "database": "unavailable"})
        return {
            "status": "ready",
            "database": "connected",
            "schema_revision": revision,
            "environment": get_settings().app_env,
            "stage": 8,
            "scanners_enabled": True,
            "ai_enabled": get_settings().ai_enabled,
        }

    frontend = get_settings().frontend_dist
    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def frontend_page(path: str):
        if path.startswith(("api", "health", "assets")):
            raise HTTPException(404, "Не найдено")
        if not (frontend / "index.html").is_file():
            raise HTTPException(503, "Frontend ещё не собран")
        return FileResponse(frontend / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
