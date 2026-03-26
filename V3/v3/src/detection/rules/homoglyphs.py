"""
Detection des homoglyphes dans les domaines.
Detecte les tentatives de typosquatting (ex: paypa1.com, g00gle.com, micr0soft.com).
"""
import re

# Mapping des caracteres similaires
HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "@": "a",
}

# Domaines cibles courants (marques les plus usurpees)
BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.fr"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "meta.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "orange": ["orange.fr"],
    "laposte": ["laposte.fr", "laposte.net"],
}


def normalize_domain(domain: str) -> str:
    """Normalise un domaine en remplacant les homoglyphes."""
    normalized = domain.lower()
    for fake, real in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def _add(anomalies: list, severite: str, description: str, scores: dict, rule: str):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_homoglyphs(email_data: dict, scores: dict) -> list[dict]:
    """Detecte les domaines qui ressemblent a des marques connues."""
    anomalies = []
    expediteur = email_data.get("expediteur", "")

    match = re.search(r"@([\w\.-]+)", expediteur)
    if not match:
        return anomalies

    domaine = match.group(1).lower()
    normalized = normalize_domain(domaine)

    # Verifier si le domaine normalise correspond a une marque
    for brand, legit_domains in BRAND_DOMAINS.items():
        if domaine in legit_domains:
            # C'est le vrai domaine, pas un homoglyphe
            continue

        for legit in legit_domains:
            legit_name = legit.split(".")[0]
            domain_name = domaine.split(".")[0]
            normalized_name = normalize_domain(domain_name)

            # Le domaine normalise ressemble a la marque mais le domaine original est different
            if normalized_name == legit_name and domain_name != legit_name:
                _add(
                    anomalies, "haute",
                    f"Homoglyphe detecte : {domaine} ressemble a {legit} (marque: {brand})",
                    scores, "homoglyph",
                )
                break

    return anomalies
