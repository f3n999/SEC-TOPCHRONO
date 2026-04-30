"""
Détection des URLs suspectes — V5
Nouveauté : règle domain_mismatch (URL dont le domaine ≠ domaine expéditeur).
Utilise tldextract pour une extraction fiable du domaine registré.
"""
import re

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


def _add(anomalies, severite, description, scores, rule):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def _get_registered_domain(url: str) -> str:
    """Extrait le domaine enregistré (ex: mableflyfull.us) depuis une URL."""
    if _TLDEXTRACT_AVAILABLE:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}".lower() if extracted.suffix else extracted.domain.lower()
    # Fallback regex simple
    match = re.search(r"https?://([^/?\s]+)", url)
    if not match:
        return ""
    host = match.group(1).lower()
    # Enlever port et sous-domaines (approximatif sans tldextract)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _get_sender_domain(expediteur: str) -> str:
    """Extrait le domaine de l'expéditeur."""
    if not expediteur or "@" not in expediteur:
        return ""
    domain = expediteur.split("@")[-1].lower()
    if _TLDEXTRACT_AVAILABLE:
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}".lower() if extracted.suffix else domain
    return domain


def check_urls(email_data: dict, rules: dict, scores: dict, expediteur: str = "") -> list[dict]:
    anomalies = []
    corps = email_data.get("corps", "")
    corps_html = email_data.get("corps_html", "")
    urls_extraites = email_data.get("urls", [])

    urls_regex = re.findall(r"https?://[^\s<>\"')]+", f"{corps} {corps_html}", re.IGNORECASE)
    urls = list(set(urls_extraites + urls_regex))

    shorteners = rules.get("url_shorteners", [])
    shortener_pattern = "|".join(re.escape(s) for s in shorteners) if shorteners else ""

    sender_domain = _get_sender_domain(expediteur)
    whitelist_domains = set(rules.get("whitelist", {}).get("domains", []))

    # Domaines d'infrastructure légitimes à ignorer pour domain_mismatch
    infra_domains = {
        "microsoft.com", "outlook.com", "office.com", "office365.com",
        "google.com", "googleapis.com", "gstatic.com",
        "w3.org", "schema.org",
    }

    seen_mismatches = set()

    for url in urls:
        url_domain = _get_registered_domain(url)
        if not url_domain:
            continue

        # URL raccourcie
        if shortener_pattern and re.search(shortener_pattern, url, re.IGNORECASE):
            _add(anomalies, "moyenne", f"URL raccourcie : {url[:80]}", scores, "shortened_url")

        # URL avec IP directe
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
            _add(anomalies, "haute", f"URL avec adresse IP : {url[:80]}", scores, "ip_url")

        # HTTP non sécurisé (hors localhost)
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            _add(anomalies, "faible", f"URL non sécurisée (HTTP) : {url[:80]}", scores, "http_url")

        # Encodage suspect
        if url.count("%") > 5:
            _add(anomalies, "moyenne", f"URL avec encodage suspect : {url[:80]}", scores, "encoded_url")

        # ── RÈGLE V5 : Domain mismatch ────────────────────────────────────────
        # L'URL pointe vers un domaine qui n'a aucun rapport avec l'expéditeur
        if (
            sender_domain
            and url_domain
            and url_domain != sender_domain
            and url_domain not in whitelist_domains
            and url_domain not in infra_domains
            and url_domain not in seen_mismatches
        ):
            seen_mismatches.add(url_domain)
            _add(
                anomalies,
                "haute",
                f"URL hors domaine expéditeur : {url_domain} (expéditeur : {sender_domain})",
                scores,
                "domain_mismatch",
            )

    return anomalies
