"""Endpoints de rapports et statistiques."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import get_session
from src.db.repository import ScanRepository

router = APIRouter()


@router.get("/reports")
async def list_reports(session: AsyncSession = Depends(get_session)):
    """Liste les derniers rapports de scan."""
    repo = ScanRepository(session)
    sessions = await repo.get_sessions(limit=20)
    return [
        {
            "id": s.id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "type": s.scan_type,
            "emails": s.emails_scanned,
            "phishing": s.phishing_count,
            "suspects": s.suspect_count,
        }
        for s in sessions
    ]


@router.get("/reports/{session_id}")
async def get_report(session_id: str, session: AsyncSession = Depends(get_session)):
    """Detail d'un rapport de scan."""
    repo = ScanRepository(session)
    results = await repo.get_session_results(session_id)
    return [
        {
            "sender": r.sender,
            "subject": r.subject,
            "received_at": r.received_at,
            "spf": r.spf,
            "dkim": r.dkim,
            "dmarc": r.dmarc,
            "score": r.risk_score,
            "level": r.risk_level,
            "action": r.action,
            "anomalies": r.anomalies,
        }
        for r in results
    ]


@router.get("/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    """Statistiques globales."""
    repo = ScanRepository(session)
    return await repo.get_stats()
