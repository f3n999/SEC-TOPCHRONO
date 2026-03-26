"""
Scheduler de scans automatiques avec APScheduler.
"""
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger

from config.settings import get_settings
from src.core.graph_client import GraphClient
from src.detection.engine import DetectionEngine
from src.core.scanner import Scanner
from src.export.api_export import send_to_server


scheduler = AsyncIOScheduler()


async def scheduled_scan():
    """Job de scan automatique."""
    logger.info("=== Scan programme demarre ===")
    settings = get_settings()

    try:
        graph = GraphClient(settings.azure)
        engine = DetectionEngine(settings.scan.rules_file)
        scanner = Scanner(graph, engine)

        # TODO: get last scan time from DB for differential scan
        scan_result = await scanner.scan_all(top=settings.scan.default_emails_per_user)

        if scan_result.results:
            # Envoyer au serveur
            send_to_server(scan_result, settings.server.remote_server, agent_id="agent-scheduler-v3")

            # Alerter si menaces HIGH
            high_count = scan_result.phishing_count
            if high_count > 0:
                logger.bind(security=True).warning(
                    "ALERTE : {} email(s) phishing detecte(s) lors du scan programme!",
                    high_count,
                )
                # TODO: envoyer webhook/email d'alerte

        logger.info(
            "=== Scan programme termine : {} emails, {} HIGH ===",
            scan_result.emails_scanned,
            scan_result.phishing_count,
        )
    except Exception as e:
        logger.error("Erreur scan programme : {}", e)


def start_scheduler(interval_minutes: int = 60):
    """Demarre le scheduler."""
    scheduler.add_job(
        scheduled_scan,
        "interval",
        minutes=interval_minutes,
        id="phishing_scan",
        name="Scan phishing automatique",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler demarre (intervalle: {} min)", interval_minutes)


def stop_scheduler():
    """Arrete le scheduler."""
    scheduler.shutdown()
    logger.info("Scheduler arrete.")


if __name__ == "__main__":
    from src.core.logger import setup_logging
    settings = get_settings()
    setup_logging(settings.log_level, settings.data_dir)
    logger.info("Demarrage du scheduler standalone...")
    start_scheduler(settings.scan.schedule_interval_minutes)

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        stop_scheduler()
