"""
Repository pattern pour les operations CRUD sur la BDD.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from loguru import logger

from src.db.models import ScanSession, ScanResultRow, WhitelistEntry, ThreatIndicator


class ScanRepository:
    """Operations CRUD pour les scans."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_scan(self, scan_result) -> str:
        """Persiste un ScanResult complet en BDD."""
        session_id = str(uuid.uuid4())

        db_session = ScanSession(
            id=session_id,
            started_at=scan_result.started_at,
            finished_at=scan_result.finished_at,
            scan_type="full",
            users_scanned=scan_result.users_scanned,
            emails_scanned=scan_result.emails_scanned,
            phishing_count=scan_result.phishing_count,
            suspect_count=scan_result.suspect_count,
            clean_count=scan_result.clean_count,
        )
        self.session.add(db_session)

        for r in scan_result.results:
            row = ScanResultRow(
                session_id=session_id,
                message_id=r.get("message_id", ""),
                user_email=r.get("boite", ""),
                sender=r.get("expediteur", ""),
                subject=r.get("sujet", ""),
                received_at=r.get("date", ""),
                spf=r.get("spf", "?"),
                dkim=r.get("dkim", "?"),
                dmarc=r.get("dmarc", "?"),
                reply_to_mismatch=r.get("reply_to_mismatch", False),
                risk_score=r.get("score", 0),
                risk_level=r.get("niveau", "LOW"),
                action=r.get("action", ""),
                anomalies=r.get("anomalies", []),
            )
            self.session.add(row)

        await self.session.commit()
        logger.info("Scan {} persiste ({} resultats)", session_id[:8], len(scan_result.results))
        return session_id

    async def get_sessions(self, limit: int = 20) -> list[ScanSession]:
        """Recupere les dernieres sessions de scan."""
        stmt = select(ScanSession).order_by(ScanSession.started_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_session_results(self, session_id: str) -> list[ScanResultRow]:
        """Recupere les resultats d'une session."""
        stmt = select(ScanResultRow).where(ScanResultRow.session_id == session_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_stats(self) -> dict:
        """Statistiques globales."""
        total_sessions = await self.session.scalar(select(func.count(ScanSession.id)))
        total_emails = await self.session.scalar(select(func.count(ScanResultRow.id)))
        total_high = await self.session.scalar(
            select(func.count(ScanResultRow.id)).where(ScanResultRow.risk_level == "HIGH")
        )
        total_medium = await self.session.scalar(
            select(func.count(ScanResultRow.id)).where(ScanResultRow.risk_level == "MEDIUM")
        )

        return {
            "total_scans": total_sessions or 0,
            "total_emails_analysed": total_emails or 0,
            "total_phishing": total_high or 0,
            "total_suspects": total_medium or 0,
        }

    async def get_last_scan_time(self) -> str | None:
        """Retourne la date du dernier scan (pour scan differentiel)."""
        stmt = select(ScanSession.finished_at).order_by(ScanSession.finished_at.desc()).limit(1)
        result = await self.session.scalar(stmt)
        if result:
            return result.isoformat() + "Z"
        return None


class WhitelistRepository:
    """Operations CRUD pour la whitelist."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def add(self, entry_type: str, value: str, reason: str = "") -> WhitelistEntry:
        entry = WhitelistEntry(entry_type=entry_type, value=value.lower(), reason=reason)
        self.session.add(entry)
        await self.session.commit()
        return entry

    async def remove(self, value: str) -> bool:
        stmt = select(WhitelistEntry).where(WhitelistEntry.value == value.lower())
        result = await self.session.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry:
            await self.session.delete(entry)
            await self.session.commit()
            return True
        return False

    async def list_all(self) -> list[WhitelistEntry]:
        stmt = select(WhitelistEntry).order_by(WhitelistEntry.added_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
