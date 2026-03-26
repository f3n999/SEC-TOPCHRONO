"""Endpoints de scan."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from loguru import logger

from config.settings import get_settings, Settings
from src.core.graph_client import GraphClient
from src.detection.engine import DetectionEngine
from src.core.scanner import Scanner

router = APIRouter()


class ScanRequest(BaseModel):
    user_id: str | None = None  # None = tous les users
    top: int = 25
    differential: bool = True  # Scan differentiel par defaut


class ScanResponse(BaseModel):
    session_id: str
    total_emails: int
    phishing_high: int
    suspects_medium: int
    legitimes_low: int
    detection_rate: str


@router.post("/scan", response_model=ScanResponse)
async def launch_scan(request: ScanRequest):
    """Lance un scan de phishing."""
    settings = get_settings()

    try:
        graph = GraphClient(settings.azure)
        engine = DetectionEngine(settings.scan.rules_file)
        scanner = Scanner(graph, engine)

        user_ids = None
        if request.user_id:
            user_ids = [(request.user_id, request.user_id)]

        since = None
        # TODO: get last scan time from DB for differential scan

        scan = await scanner.scan_all(user_ids=user_ids, top=request.top, since=since)
        summary = scan.summary()

        return ScanResponse(
            session_id=summary.get("session_id", ""),
            total_emails=summary["total_emails"],
            phishing_high=summary["phishing_high"],
            suspects_medium=summary["suspects_medium"],
            legitimes_low=summary["legitimes_low"],
            detection_rate=summary["detection_rate"],
        )
    except Exception as e:
        logger.error("Erreur scan API : {}", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/users")
async def list_users():
    """Liste les utilisateurs disponibles."""
    settings = get_settings()
    try:
        graph = GraphClient(settings.azure)
        users = await graph.list_users()
        return [
            {
                "id": u.id,
                "display_name": u.display_name,
                "email": u.mail,
                "upn": u.user_principal_name,
            }
            for u in users
        ]
    except Exception as e:
        logger.error("Erreur list users : {}", e)
        raise HTTPException(status_code=500, detail=str(e))
