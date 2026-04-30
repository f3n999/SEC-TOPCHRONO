"""
Détection des homoglyphes — V5
Double couche :
  1. confusable_homoglyphs  → Unicode confusables (ex: Cyrillic 'а' ≈ Latin 'a')
  2. ASCII_MAP maison       → substitutions chiffres/lettres (0→o, 1→l, 3→e…)
"""
import re

try:
    from confusable_homoglyphs import confusables
    _CONFUSABLE_AVAILABLE = True
except ImportError:
    _CONFUSABLE_AVAILABLE = False

# Substitutions ASCII classiques du phishing
ASCII_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b",
}

BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "hotmail.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.fr", "amazon.co.uk"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "meta.com", "instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "orange": ["orange.fr"],
    "laposte": ["laposte.fr", "laposte.net"],
    "sfr": ["sfr.fr"],
    "ameli": ["ameli.fr"],
    "impots": ["impots.gouv.fr"],
    "caf": ["caf.fr"],
}


def _add(anomalies, severite, description, scores, rule):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def _normalize_ascii(domain: str) -> str:
    normalized = domain.lower()
    for fake, real in ASCII_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def check_homoglyphs(email_data: dict, scores: dict) -> list[dict]:
    anomalies = []
    expediteur = email_data.get("expediteur", "")

    match = re.search(r"@([\w.\-]+)", expediteur)
    if not match:
        return anomalies

    domaine = match.group(1).lower()
    domain_name = domaine.split(".")[0]
    normalized_name = _normalize_ascii(domain_name)

    # ── Couche 1 : ASCII substitutions ────────────────────────────────────────
    for brand, legit_domains in BRAND_DOMAINS.items():
        if domaine in legit_domains:
            continue  # C'est le vrai domaine

        for legit in legit_domains:
            legit_name = legit.split(".")[0]
            if normalized_name == legit_name and domain_name != legit_name:
                _add(
                    anomalies, "haute",
                    f"Homoglyphe ASCII : {domaine} imite {legit} (marque : {brand})",
                    scores, "homoglyph_ascii",
                )
                break

    # ── Couche 2 : Unicode confusables ────────────────────────────────────────
    if _CONFUSABLE_AVAILABLE:
        try:
            result = confusables.is_dangerous(domaine)
            if result:
                _add(
                    anomalies, "haute",
                    f"Homoglyphe Unicode détecté dans le domaine : {domaine}",
                    scores, "homoglyph_unicode",
                )
        except Exception:
            pass

    return anomalies
