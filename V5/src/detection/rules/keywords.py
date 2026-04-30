"""Détection des mots-clés de phishing."""
import re


def _add(anomalies, severite, description, scores, rule):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_keywords(email_data: dict, rules: dict, scores: dict) -> list[dict]:
    anomalies = []
    sujet = email_data.get("sujet", "").lower()
    corps = email_data.get("corps", "").lower()
    corps_html = email_data.get("corps_html", "").lower()
    texte = f"{sujet} {corps} {corps_html}"

    thresholds = rules.get("thresholds", {})
    seuil_high = thresholds.get("keywords_high", 3)
    seuil_medium = thresholds.get("keywords_medium", 2)

    keywords_config = rules.get("keywords", {})
    all_keywords = []
    for category_words in keywords_config.values():
        if isinstance(category_words, list):
            all_keywords.extend(category_words)

    mots_trouves = []
    for mot in all_keywords:
        if re.search(rf"\b{re.escape(mot)}\b", texte, re.IGNORECASE):
            mots_trouves.append(mot)

    if len(mots_trouves) >= seuil_high:
        _add(
            anomalies, "haute",
            f"Multiples mots-clés phishing ({len(mots_trouves)}) : {', '.join(mots_trouves[:5])}",
            scores, "keywords_high",
        )
    elif len(mots_trouves) >= seuil_medium:
        _add(
            anomalies, "moyenne",
            f"Mots-clés suspects ({len(mots_trouves)}) : {', '.join(mots_trouves)}",
            scores, "keywords_medium",
        )

    return anomalies
