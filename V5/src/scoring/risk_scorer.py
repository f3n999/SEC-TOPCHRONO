"""Scoring de risque V5 — compatible avec les bonus de whitelist (scores négatifs)."""

RISK_LEVELS = {
    "LOW":    {"threshold": 30,  "action": "ALLOW  — Email probablement légitime"},
    "MEDIUM": {"threshold": 60,  "action": "REVIEW — Vérification humaine recommandée"},
    "HIGH":   {"threshold": 100, "action": "BLOCK  — Phishing probable, multiples indicateurs"},
}


def compute_raw_score(anomalies: list[dict]) -> int:
    return sum(a.get("score", 0) for a in anomalies)


def normalize_score(raw_score: int, cap: int = 100) -> int:
    return max(0, min(cap, raw_score))


def determine_risk_level(score: int) -> str:
    if score <= RISK_LEVELS["LOW"]["threshold"]:
        return "LOW"
    elif score <= RISK_LEVELS["MEDIUM"]["threshold"]:
        return "MEDIUM"
    return "HIGH"


def determine_action(risk_level: str) -> str:
    return RISK_LEVELS.get(risk_level, {}).get("action", "UNKNOWN")


def score_email(anomalies: list[dict]) -> dict:
    raw = compute_raw_score(anomalies)
    score = normalize_score(raw)
    niveau = determine_risk_level(score)
    action = determine_action(niveau)

    # Exclure le bonus whitelist du rapport des règles déclenchées
    rules_triggered = [
        a.get("rule", "unknown")
        for a in anomalies
        if a.get("rule") != "whitelist_bonus"
    ]

    return {
        "score": score,
        "raw_score": raw,
        "niveau": niveau,
        "action": action,
        "rules_triggered": rules_triggered,
        "anomalies_count": len([a for a in anomalies if a.get("rule") != "whitelist_bonus"]),
    }
