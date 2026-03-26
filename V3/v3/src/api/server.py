"""
API REST FastAPI v3.0
Expose les endpoints de scan, rapports et statistiques.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from loguru import logger

from config.settings import get_settings
from src.core.logger import setup_logging
from src.db.database import init_db, close_db
from src.api.routes.scan import router as scan_router
from src.api.routes.reports import router as reports_router
from src.api.routes.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup et shutdown de l'API."""
    settings = get_settings()
    setup_logging(settings.log_level, settings.data_dir)
    await init_db(settings.database.url, settings.database.echo)
    logger.info("API demarree sur {}:{}", settings.server.host, settings.server.port)
    yield
    await close_db()
    logger.info("API arretee.")


app = FastAPI(
    title="Phishing Detection Agent",
    version="3.0.0",
    description="API de detection de phishing via Microsoft Graph API",
    lifespan=lifespan,
)

app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(scan_router, prefix="/api", tags=["Scan"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "src.api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=True,
    )
