"""Detection des URLs suspectes."""
import re


def _add(anomalies: list, severite: str, description: str, scores: dict, rule: str):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_urls(email_data: dict, rules: dict, scores: dict) -> list[dict]:
    """Analyse les URLs dans le corps de l'email."""
    anomalies = []
    corps = email_data.get("corps", "")
    corps_html = email_data.get("corps_html", "")
    urls_extraites = email_data.get("urls", [])

    # Extraire toutes les URLs
    urls_regex = re.findall(r"https?://[^\s<>\"']+", f"{corps} {corps_html}", re.IGNORECASE)
    urls = list(set(urls_extraites + urls_regex))

    shorteners = rules.get("url_shorteners", [])
    shortener_pattern = "|".join(re.escape(s) for s in shorteners) if shorteners else ""

    for url in urls:
        # URL raccourcie
        if shortener_pattern and re.search(shortener_pattern, url, re.IGNORECASE):
            _add(anomalies, "moyenne", f"URL raccourcie : {url[:80]}", scores, "shortened_url")

        # URL avec IP directe
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            _add(anomalies, "haute", f"URL avec adresse IP : {url[:80]}", scores, "ip_url")

        # HTTP non securise
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            _add(anomalies, "faible", f"URL non securisee (HTTP) : {url[:80]}", scores, "http_url")

        # URL avec encodage suspect (%xx excessif)
        percent_count = url.count("%")
        if percent_count > 5:
            _add(anomalies, "moyenne", f"URL avec encodage suspect ({percent_count}x) : {url[:80]}", scores, "encoded_url")

    return anomalies
