"""
Configuration de la base de donnees SQLAlchemy async.
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from loguru import logger

from src.db.models import Base

_engine = None
_session_factory = None


async def init_db(database_url: str, echo: bool = False):
    """Initialise la connexion BDD et cree les tables."""
    global _engine, _session_factory

    _engine = create_async_engine(database_url, echo=echo)
    _session_factory = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Base de donnees initialisee ({})", database_url.split("///")[-1])


async def get_session() -> AsyncSession:
    """Retourne une session BDD."""
    if _session_factory is None:
        raise RuntimeError("Base de donnees non initialisee. Appelez init_db() d'abord.")
    async with _session_factory() as session:
        yield session


async def close_db():
    """Ferme la connexion BDD."""
    global _engine
    if _engine:
        await _engine.dispose()
        logger.info("Connexion BDD fermee.")
