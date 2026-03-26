"""
Scanner orchestrateur v3.0
Coordonne : Graph API -> Detection -> Scoring -> Persistance -> Export.
"""
from datetime import datetime, timezone

from loguru import logger

from src.core.graph_client import GraphClient, message_to_dict
from src.detection.engine import DetectionEngine
from src.scoring.risk_scorer import score_email
from src.db.repository import ScanRepository


class ScanResult:
    """Resultat d'un scan complet."""

    def __init__(self):
        self.session_id: str = ""
        self.started_at: datetime = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.users_scanned: int = 0
        self.emails_scanned: int = 0
        self.results: list[dict] = []

    @property
    def phishing_count(self) -> int:
        return sum(1 for r in self.results if r["niveau"] == "HIGH")

    @property
    def suspect_count(self) -> int:
        return sum(1 for r in self.results if r["niveau"] == "MEDIUM")

    @property
    def clean_count(self) -> int:
        return sum(1 for r in self.results if r["niveau"] == "LOW")

    def summary(self) -> dict:
        total = len(self.results)
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "users_scanned": self.users_scanned,
            "total_emails": total,
            "phishing_high": self.phishing_count,
            "suspects_medium": self.suspect_count,
            "legitimes_low": self.clean_count,
            "detection_rate": f"{(self.phishing_count + self.suspect_count) / max(total, 1) * 100:.1f}%",
        }


class Scanner:
    """Orchestrateur de scan."""

    def __init__(
        self,
        graph: GraphClient,
        engine: DetectionEngine,
        repo: ScanRepository | None = None,
    ):
        self.graph = graph
        self.engine = engine
        self.repo = repo

    async def scan_user(
        self,
        user_id: str,
        user_name: str,
        top: int = 25,
        since: str | None = None,
    ) -> list[dict]:
        """Scanne les emails d'un utilisateur."""
        logger.info("Scan de {} ({} emails max)", user_name, top)

        try:
            messages = await self.graph.list_user_messages(user_id, top=top, since=since)
        except Exception:
            logger.warning("Impossible de scanner {}", user_name)
            return []

        if not messages:
            logger.info("  Aucun email pour {}", user_name)
            return []

        results = []
        for msg in messages:
            data = message_to_dict(msg)
            anomalies = self.engine.analyser(data)
            evaluation = score_email(anomalies)

            result = {
                "message_id": data["message_id"],
                "boite": user_name,
                "date": data["date"],
                "expediteur": data["expediteur"],
                "sujet": data["sujet"],
                "spf": data["spf"],
                "dkim": data["dkim"],
                "dmarc": data["dmarc"],
                "reply_to_mismatch": bool(
                    data["reply_to"]
                    and data["reply_to"].lower() != data["expediteur"].lower()
                ),
                "score": evaluation["score"],
                "niveau": evaluation["niveau"],
                "action": evaluation["action"],
                "anomalies": anomalies,
            }
            results.append(result)

            # Log securite pour les menaces HIGH
            if evaluation["niveau"] == "HIGH":
                logger.bind(security=True).warning(
                    "PHISHING detecte | De: {} | Sujet: {} | Score: {}/100",
                    data["expediteur"],
                    data["sujet"][:50],
                    evaluation["score"],
                )

        logger.info(
            "  {} emails analyses pour {} (HIGH:{}, MEDIUM:{}, LOW:{})",
            len(results),
            user_name,
            sum(1 for r in results if r["niveau"] == "HIGH"),
            sum(1 for r in results if r["niveau"] == "MEDIUM"),
            sum(1 for r in results if r["niveau"] == "LOW"),
        )
        return results

    async def scan_all(
        self,
        user_ids: list[tuple[str, str]] | None = None,
        top: int = 25,
        since: str | None = None,
    ) -> ScanResult:
        """
        Scan complet de plusieurs utilisateurs.

        Args:
            user_ids: Liste de (user_id, display_name). Si None, scanne tous les users.
            top: Nombre max d'emails par utilisateur
            since: Date ISO pour scan differentiel
        """
        scan = ScanResult()
        logger.info("=== Debut scan complet ===")

        # Si pas de users specifies, recuperer tous
        if user_ids is None:
            users = await self.graph.list_users()
            user_ids = [
                (u.user_principal_name or u.id, u.display_name or u.user_principal_name or u.id)
                for u in users
            ]

        scan.users_scanned = len(user_ids)

        for uid, name in user_ids:
            results = await self.scan_user(uid, name, top=top, since=since)
            scan.results.extend(results)

        scan.emails_scanned = len(scan.results)
        scan.finished_at = datetime.now(timezone.utc)

        # Persister en BDD si disponible
        if self.repo:
            scan.session_id = await self.repo.save_scan(scan)
            logger.info("Scan persiste en BDD (session: {})", scan.session_id)

        logger.info(
            "=== Scan termine : {} emails, {} HIGH, {} MEDIUM ===",
            scan.emails_scanned,
            scan.phishing_count,
            scan.suspect_count,
        )
        return scan
