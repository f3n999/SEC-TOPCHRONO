"""
PHISHING DETECTION SERVER v1.0
FastAPI backend - Recoit les resultats de scan, stocke en SQLite.
Deployer sur la machine Linux (192.168.237.133).
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import sqlite3
import json
import os

# ── Config ──
DB_PATH = os.environ.get("DB_PATH", "phishing_agent.db")

app = FastAPI(
    title="Phishing Detection API",
    description="Backend de stockage et consultation des scans email",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ──

class ScanResult(BaseModel):
    boite: str
    date: str
    expediteur: str
    sujet: str
    spf: str = "?"
    dkim: str = "?"
    dmarc: str = "?"
    reply_to_mismatch: bool = False
    score: int = 0
    niveau: str = "LOW"
    action: str = ""
    anomalies: list = []


class ScanBatch(BaseModel):
    agent_id: str = "default"
    scan_date: Optional[str] = None
    results: list[ScanResult]


# ── Database ──

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            total_emails INTEGER DEFAULT 0,
            phishing_count INTEGER DEFAULT 0,
            suspect_count INTEGER DEFAULT 0,
            legitime_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            boite TEXT,
            date_reception TEXT,
            expediteur TEXT,
            sujet TEXT,
            spf TEXT DEFAULT '?',
            dkim TEXT DEFAULT '?',
            dmarc TEXT DEFAULT '?',
            reply_to_mismatch INTEGER DEFAULT 0,
            score INTEGER DEFAULT 0,
            niveau TEXT DEFAULT 'LOW',
            action TEXT DEFAULT '',
            anomalies TEXT DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_detections_niveau ON detections(niveau);
        CREATE INDEX IF NOT EXISTS idx_detections_scan ON detections(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date);
    """)
    conn.close()


init_db()


# ── API Routes ──

@app.get("/")
def root():
    return {
        "service": "Phishing Detection API",
        "version": "1.0.0",
        "status": "running",
        "db": DB_PATH
    }


@app.get("/api/health")
def health():
    """Verifie que le serveur et la DB fonctionnent."""
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ok", "db": "connected"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan")
def receive_scan(batch: ScanBatch):
    """Recoit un batch de resultats de scan et les stocke en DB."""
    conn = get_db()
    scan_date = batch.scan_date or datetime.now().isoformat()

    # Compter les niveaux
    high = sum(1 for r in batch.results if r.niveau == "HIGH")
    medium = sum(1 for r in batch.results if r.niveau == "MEDIUM")
    low = sum(1 for r in batch.results if r.niveau == "LOW")

    # Inserer le scan
    cursor = conn.execute(
        """INSERT INTO scans (agent_id, scan_date, total_emails, phishing_count, suspect_count, legitime_count)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (batch.agent_id, scan_date, len(batch.results), high, medium, low)
    )
    scan_id = cursor.lastrowid

    # Inserer chaque detection
    for r in batch.results:
        conn.execute(
            """INSERT INTO detections 
               (scan_id, boite, date_reception, expediteur, sujet, spf, dkim, dmarc,
                reply_to_mismatch, score, niveau, action, anomalies)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, r.boite, r.date, r.expediteur, r.sujet,
             r.spf, r.dkim, r.dmarc, int(r.reply_to_mismatch),
             r.score, r.niveau, r.action, json.dumps(r.anomalies, ensure_ascii=False))
        )

    conn.commit()
    conn.close()

    return {
        "status": "ok",
        "scan_id": scan_id,
        "total_stored": len(batch.results),
        "summary": {
            "phishing": high,
            "suspect": medium,
            "legitime": low
        }
    }


@app.get("/api/scans")
def list_scans(limit: int = 20):
    """Liste les derniers scans."""
    conn = get_db()
    rows = conn.execute(
        """SELECT id, agent_id, scan_date, total_emails, phishing_count, 
                  suspect_count, legitime_count, created_at
           FROM scans ORDER BY id DESC LIMIT ?""", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def get_scan_details(scan_id: int):
    """Details d'un scan specifique avec toutes les detections."""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    detections = conn.execute(
        "SELECT * FROM detections WHERE scan_id = ? ORDER BY score DESC", (scan_id,)
    ).fetchall()
    conn.close()

    return {
        "scan": dict(scan),
        "detections": [dict(d) for d in detections]
    }


@app.get("/api/stats")
def global_stats():
    """Statistiques globales de tous les scans."""
    conn = get_db()

    # Totaux
    totals = conn.execute("""
        SELECT 
            COUNT(*) as total_scans,
            COALESCE(SUM(total_emails), 0) as total_emails,
            COALESCE(SUM(phishing_count), 0) as total_phishing,
            COALESCE(SUM(suspect_count), 0) as total_suspects,
            COALESCE(SUM(legitime_count), 0) as total_legitimes
        FROM scans
    """).fetchone()

    # Top domaines suspects
    top_domains = conn.execute("""
        SELECT expediteur, COUNT(*) as count, AVG(score) as avg_score
        FROM detections 
        WHERE niveau IN ('HIGH', 'MEDIUM')
        GROUP BY expediteur
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Tendance par jour
    daily = conn.execute("""
        SELECT 
            DATE(scan_date) as jour,
            SUM(total_emails) as emails,
            SUM(phishing_count) as phishing,
            SUM(suspect_count) as suspects
        FROM scans
        GROUP BY DATE(scan_date)
        ORDER BY jour DESC
        LIMIT 30
    """).fetchall()

    conn.close()

    total_emails = totals['total_emails']
    total_flagged = totals['total_phishing'] + totals['total_suspects']

    return {
        "totals": dict(totals),
        "detection_rate": f"{total_flagged / max(total_emails, 1) * 100:.1f}%",
        "top_suspicious_senders": [dict(d) for d in top_domains],
        "daily_trend": [dict(d) for d in daily]
    }


@app.get("/api/detections")
def list_detections(niveau: Optional[str] = None, limit: int = 50):
    """Liste les detections, filtrable par niveau."""
    conn = get_db()
    if niveau:
        rows = conn.execute(
            "SELECT * FROM detections WHERE niveau = ? ORDER BY id DESC LIMIT ?",
            (niveau.upper(), limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn
    print(f"[SERVER] Demarrage sur http://0.0.0.0:8000")
    print(f"[SERVER] Base de donnees : {DB_PATH}")
    print(f"[SERVER] Documentation API : http://0.0.0.0:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
