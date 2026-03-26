"""Export JSON."""
import json
import os
from datetime import datetime
from loguru import logger


def export_json(scan_result, output_dir: str = "data") -> str:
    """Exporte les resultats en JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"scan_{timestamp}.json")

    rapport = {
        "scan_date": datetime.now().isoformat(),
        "summary": scan_result.summary(),
        "details": scan_result.results,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False, default=str)

    logger.info("Export JSON : {}", filepath)
    return filepath
