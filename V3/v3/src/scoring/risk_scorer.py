"""
Scoring de risque v3.0
- Poids configurables par type de regle
- Score normalise 0-100
- Niveaux de risque avec actions recommandees
"""


RISK_LEVELS = {
    "LOW": {"threshold": 30, "action": "ALLOW - Email probablement legitime"},
    "MEDIUM": {"threshold": 60, "action": "REVIEW - Verification humaine recommandee"},
    "HIGH": {"threshold": 100, "action": "BLOCK - Phishing probable, multiples indicateurs"},
}


def compute_raw_score(anomalies: list[dict]) -> int:
    """Additionne les scores de toutes les anomalies."""
    return sum(a.get("score", 0) for a in anomalies)


def normalize_score(raw_score: int, cap: int = 100) -> int:
    """Normalise le score entre 0 et cap."""
    return max(0, min(cap, raw_score))


def determine_risk_level(score: int) -> str:
    """Determine le niveau de risque."""
    if score <= RISK_LEVELS["LOW"]["threshold"]:
        return "LOW"
    elif score <= RISK_LEVELS["MEDIUM"]["threshold"]:
        return "MEDIUM"
    return "HIGH"


def determine_action(risk_level: str) -> str:
    """Retourne l'action recommandee."""
    return RISK_LEVELS.get(risk_level, {}).get("action", "UNKNOWN")


def score_email(anomalies: list[dict]) -> dict:
    """Pipeline complet de scoring."""
    raw = compute_raw_score(anomalies)
    score = normalize_score(raw)
    niveau = determine_risk_level(score)
    action = determine_action(niveau)

    return {
        "score": score,
        "raw_score": raw,
        "niveau": niveau,
        "action": action,
        "rules_triggered": [a.get("rule", "unknown") for a in anomalies],
        "anomalies_count": len(anomalies),
    }
