"""
URLScan.io V5 — scan automatique des URLs suspectes.
Clé chargée depuis config/secrets.yaml (urlscan_api_key).
"""
import time

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

from src.options.secrets import get as _secret

URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
POLL_DELAY = 10
POLL_MAX = 6


def check_urlscan(urls: list[str]) -> dict[str, dict]:
    """
    Soumet des URLs à URLScan.io et récupère les verdicts.
    Retourne {url: {verdict, score, report_url}}.
    """
    if not _REQUESTS_AVAILABLE:
        return {u: {"verdict": "error", "note": "pip install requests"} for u in urls}

    api_key = _secret("urlscan_api_key", "URLSCAN_API_KEY")
    if not api_key:
        return {u: {"verdict": "error", "note": "Clé URLScan manquante"} for u in urls}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    results = {}

    for url in urls:
        try:
            resp = requests.post(
                URLSCAN_SUBMIT,
                headers=headers,
                json={"url": url, "visibility": "private"},
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                results[url] = {"verdict": "error", "note": f"HTTP {resp.status_code}"}
                continue

            uuid = resp.json().get("uuid")
            if not uuid:
                results[url] = {"verdict": "error", "note": "UUID manquant"}
                continue

            for _ in range(POLL_MAX):
                time.sleep(POLL_DELAY)
                res = requests.get(URLSCAN_RESULT.format(uuid=uuid), timeout=10)
                if res.status_code == 200:
                    verdicts = res.json().get("verdicts", {}).get("overall", {})
                    results[url] = {
                        "verdict": "MALVEILLANT" if verdicts.get("malicious") else "OK",
                        "score": verdicts.get("score", 0),
                        "report_url": f"https://urlscan.io/result/{uuid}/",
                    }
                    break
            else:
                results[url] = {"verdict": "timeout", "note": "Résultat non dispo après 60s"}

        except Exception as e:
            results[url] = {"verdict": "error", "note": str(e)}

    return results
