"""
Scoring de risque email - v2.0
Calcule un score normalise 0-100 a partir des anomalies detectees.
"""


def compute_raw_score(triggered_rules: list) -> int:
    """Additionne les scores de toutes les anomalies."""
    return sum(rule.get("score", 0) for rule in triggered_rules)


def normalize_score(raw_score: int) -> int:
    """Normalise le score entre 0 et 100."""
    return max(0, min(100, raw_score))


def determine_risk_level(final_score: int) -> str:
    """Determine le niveau de risque en fonction du score."""
    if final_score <= 30:
        return 'LOW'
    elif final_score <= 60:
        return 'MEDIUM'
    else:
        return 'HIGH'


def determine_action(risk_level: str) -> str:
    """Determine l'action recommandee."""
    actions = {
        'LOW': 'ALLOW - Email probablement legitime',
        'MEDIUM': 'REVIEW - Verification humaine recommandee',
        'HIGH': 'BLOCK - Phishing probable, multiples indicateurs'
    }
    return actions.get(risk_level, 'UNKNOWN')


def score_email(triggered_rules: list) -> dict:
    """Pipeline complet de scoring."""
    raw_score = compute_raw_score(triggered_rules)
    final_score = normalize_score(raw_score)
    risk_level = determine_risk_level(final_score)
    action = determine_action(risk_level)

    return {
        "score": final_score,
        "niveau": risk_level,
        "action": action,
        "rules_triggered": triggered_rules
    }
