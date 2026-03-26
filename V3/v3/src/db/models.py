"""
Modeles SQLAlchemy v3.0
Tables : scan_sessions, scan_results, whitelist.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class ScanSession(Base):
    """Session de scan (un run complet)."""
    __tablename__ = "scan_sessions"

    id = Column(String(36), primary_key=True)
    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)
    scan_type = Column(String(20), nullable=False, default="full")  # quick, full, scheduled
    users_scanned = Column(Integer, default=0)
    emails_scanned = Column(Integer, default=0)
    phishing_count = Column(Integer, default=0)
    suspect_count = Column(Integer, default=0)
    clean_count = Column(Integer, default=0)

    results = relationship("ScanResultRow", back_populates="session", cascade="all, delete-orphan")


class ScanResultRow(Base):
    """Resultat d'analyse d'un email."""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("scan_sessions.id"), nullable=False)
    message_id = Column(String(200), nullable=True)
    user_email = Column(String(200), nullable=False)
    sender = Column(String(200), nullable=False)
    subject = Column(String(500), nullable=True)
    received_at = Column(String(20), nullable=True)
    spf = Column(String(10), default="?")
    dkim = Column(String(10), default="?")
    dmarc = Column(String(10), default="?")
    reply_to_mismatch = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(10), default="LOW")
    action = Column(String(100), nullable=True)
    anomalies = Column(JSON, nullable=True)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    session = relationship("ScanSession", back_populates="results")


class WhitelistEntry(Base):
    """Entree de whitelist."""
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_type = Column(String(20), nullable=False)  # domain, email, ip
    value = Column(String(200), nullable=False, unique=True)
    reason = Column(String(500), nullable=True)
    added_by = Column(String(100), default="system")
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ThreatIndicator(Base):
    """Indicateur de menace (URL, domaine, IP suspecte)."""
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(20), nullable=False)  # url, domain, ip, hash
    value = Column(String(500), nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    hit_count = Column(Integer, default=1)
    risk_level = Column(String(10), default="MEDIUM")
