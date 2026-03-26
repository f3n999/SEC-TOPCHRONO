"""Export vers le serveur REST distant (VM Linux)."""
import requests
from datetime import datetime
from loguru import logger


def send_to_server(scan_result, server_url: str, agent_id: str = "agent-windows-v3") -> dict:
    """Envoie les resultats au serveur Linux via l'API REST."""
    url = f"{server_url}/api/scan"

    payload = {
        "agent_id": agent_id,
        "agent_version": "3.0.0",
        "scan_date": datetime.now().isoformat(),
        "summary": scan_result.summary(),
        "results": scan_result.results,
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            logger.info(
                "Envoye au serveur ! Scan ID: {} ({} resultats)",
                data.get("scan_id"),
                data.get("total_stored"),
            )
            return data
        else:
            logger.error("Serveur HTTP {} : {}", response.status_code, response.text[:100])
            return {"status": "error", "code": response.status_code}
    except requests.exceptions.ConnectionError:
        logger.warning("Connexion impossible a {} - serveur demarre?", server_url)
        return {"status": "connection_error"}
    except Exception as e:
        logger.error("Erreur envoi serveur : {}", e)
        return {"status": "error", "detail": str(e)}


def export_all(scan_result, server_url: str, output_dir: str = "data") -> dict:
    """Export complet : JSON + CSV + Serveur."""
    from src.export.json_export import export_json
    from src.export.csv_export import export_csv
    from src.export.console import print_scan_result

    print_scan_result(scan_result)
    json_path = export_json(scan_result, output_dir)
    csv_path = export_csv(scan_result, output_dir)
    server_response = send_to_server(scan_result, server_url)

    return {"json": json_path, "csv": csv_path, "server": server_response}
