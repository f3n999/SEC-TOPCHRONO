"""
VirusTotal V5 — vérification automatique des URLs.
Clé chargée depuis config/secrets.yaml (virustotal_api_key).
"""
import base64
import time

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

from src.options.secrets import get as _secret

VT_API_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_DELAY = 15  # quota gratuit : 4 req/min


def check_virustotal(urls: list[str]) -> dict[str, dict]:
    """
    Vérifie une liste d'URLs sur VirusTotal.
    Retourne {url: {malicious, suspicious, verdict}}.
    """
    if not _REQUESTS_AVAILABLE:
        return {u: {"verdict": "error", "note": "pip install requests"} for u in urls}

    api_key = _secret("virustotal_api_key", "VT_API_KEY")
    if not api_key:
        return {u: {"verdict": "error", "note": "Clé VT manquante"} for u in urls}

    headers = {"x-apikey": api_key}
    results = {}

    for i, url in enumerate(urls):
        if i > 0:
            time.sleep(RATE_LIMIT_DELAY)
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
            resp = requests.get(f"{VT_API_BASE}/urls/{url_id}", headers=headers, timeout=10)

            if resp.status_code == 404:
                requests.post(f"{VT_API_BASE}/urls", headers=headers, data={"url": url}, timeout=10)
                results[url] = {"verdict": "submitted", "malicious": 0, "note": "Soumis pour analyse"}
                continue

            if resp.status_code != 200:
                results[url] = {"verdict": "error", "malicious": 0, "note": f"HTTP {resp.status_code}"}
                continue

            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            results[url] = {
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "verdict": "MALVEILLANT" if malicious > 0 else ("SUSPECT" if suspicious > 0 else "OK"),
            }
        except Exception as e:
            results[url] = {"verdict": "error", "malicious": 0, "note": str(e)}

    return results
