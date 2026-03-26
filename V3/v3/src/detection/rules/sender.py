"""Verification de l'expediteur et du domaine."""
import re


def _add(anomalies: list, severite: str, description: str, scores: dict, rule: str):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_sender(email_data: dict, rules: dict, scores: dict) -> list[dict]:
    """Analyse l'expediteur pour detecter les anomalies."""
    anomalies = []
    expediteur = email_data.get("expediteur", "")
    reply_to = email_data.get("reply_to", "")
    thresholds = rules.get("thresholds", {})

    match_domaine = re.search(r"@([\w\.-]+)", expediteur)
    if match_domaine:
        domaine = match_domaine.group(1).lower()

        # Trop de tirets
        max_hyphens = thresholds.get("domain_hyphens", 2)
        if domaine.count("-") > max_hyphens:
            _add(anomalies, "moyenne", f"Domaine suspect (>{max_hyphens} tirets) : {domaine}", scores, "domain_hyphens")

        # Trop de chiffres
        max_digits = thresholds.get("domain_digits", 3)
        if sum(c.isdigit() for c in domaine) > max_digits:
            _add(anomalies, "moyenne", f"Domaine suspect (>{max_digits} chiffres) : {domaine}", scores, "domain_digits")

        # TLD suspect
        tld = domaine.split(".")[-1] if "." in domaine else ""
        suspicious_tlds = rules.get("suspicious_tlds", [])
        if tld in suspicious_tlds:
            _add(anomalies, "moyenne", f"TLD suspect : .{tld} ({domaine})", scores, "suspicious_tld")

    # Reply-To different du From
    if reply_to and reply_to.lower() != expediteur.lower():
        _add(anomalies, "haute", f"Reply-To different du From : {reply_to}", scores, "reply_to_mismatch")

    return anomalies
