"""Health check endpoint."""
from fastapi import APIRouter
from src import __version__

router = APIRouter()


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "version": __version__,
        "service": "phishing-detection-agent",
    }
