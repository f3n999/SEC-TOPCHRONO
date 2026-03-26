"""Verification SPF / DKIM / DMARC."""


def _add(anomalies: list, severite: str, description: str, scores: dict, rule: str):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_auth_headers(email_data: dict, scores: dict) -> list[dict]:
    """Verifie les resultats d'authentification SPF/DKIM/DMARC."""
    anomalies = []
    spf = email_data.get("spf", "?").upper()
    dkim = email_data.get("dkim", "?").upper()
    dmarc = email_data.get("dmarc", "?").upper()

    # SPF
    if spf == "FAIL":
        _add(anomalies, "haute", "SPF FAIL : serveur expediteur non autorise", scores, "spf_fail")
    elif spf == "SOFTFAIL":
        _add(anomalies, "moyenne", "SPF SOFTFAIL : serveur probablement non autorise", scores, "spf_softfail")
    elif spf == "NONE":
        _add(anomalies, "faible", "SPF NONE : aucun enregistrement SPF configure", scores, "spf_none")

    # DKIM
    if dkim == "FAIL":
        _add(anomalies, "haute", "DKIM FAIL : signature du mail invalide", scores, "dkim_fail")
    elif dkim == "NONE":
        _add(anomalies, "faible", "DKIM NONE : aucune signature DKIM", scores, "dkim_none")

    # DMARC
    if dmarc == "FAIL":
        _add(anomalies, "haute", "DMARC FAIL : politique du domaine rejette ce mail", scores, "dmarc_fail")
    elif dmarc == "NONE":
        _add(anomalies, "faible", "DMARC NONE : aucune politique DMARC", scores, "dmarc_none")

    return anomalies
