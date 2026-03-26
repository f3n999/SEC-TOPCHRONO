"""
Logging centralise avec loguru.
Rotation automatique, format structure, niveaux configurables.
"""
import sys
from loguru import logger


def setup_logging(level: str = "INFO", log_dir: str = "data"):
    """Configure loguru pour l'agent."""
    # Supprimer le handler par defaut
    logger.remove()

    # Console : colore et concis
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # Fichier : complet avec rotation
    logger.add(
        f"{log_dir}/agent.log",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        encoding="utf-8",
    )

    # Fichier securite : uniquement les alertes HIGH
    logger.add(
        f"{log_dir}/security.log",
        level="WARNING",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
        rotation="5 MB",
        retention="90 days",
        filter=lambda record: "security" in record["extra"],
        encoding="utf-8",
    )

    return logger
