"""Export CSV compatible Excel."""
import csv
import os
from datetime import datetime
from loguru import logger


def export_csv(scan_result, output_dir: str = "data") -> str:
    """Exporte les resultats en CSV avec separateur ; pour Excel FR."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"scan_{timestamp}.csv")

    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow([
            "Boite", "Date", "Expediteur", "Sujet",
            "SPF", "DKIM", "DMARC", "Reply-To mismatch",
            "Score", "Niveau", "Action", "Anomalies",
        ])
        for r in scan_result.results:
            anomalies_str = " | ".join(
                f"[{a['severite']}] {a['description']}" for a in r.get("anomalies", [])
            )
            writer.writerow([
                r.get("boite", ""),
                r.get("date", ""),
                r.get("expediteur", ""),
                r.get("sujet", ""),
                r.get("spf", "?"),
                r.get("dkim", "?"),
                r.get("dmarc", "?"),
                "OUI" if r.get("reply_to_mismatch") else "NON",
                r.get("score", 0),
                r.get("niveau", "?"),
                r.get("action", "?"),
                anomalies_str,
            ])

    logger.info("Export CSV : {}", filepath)
    return filepath
