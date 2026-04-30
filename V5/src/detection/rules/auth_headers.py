"""Vérification SPF / DKIM / DMARC."""


def _add(anomalies, severite, description, scores, rule):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_auth_headers(email_data: dict, scores: dict) -> list[dict]:
    anomalies = []
    spf = email_data.get("spf", "?").upper()
    dkim = email_data.get("dkim", "?").upper()
    dmarc = email_data.get("dmarc", "?").upper()

    if spf == "FAIL":
        _add(anomalies, "haute", "SPF FAIL : serveur expéditeur non autorisé", scores, "spf_fail")
    elif spf == "SOFTFAIL":
        _add(anomalies, "moyenne", "SPF SOFTFAIL : serveur probablement non autorisé", scores, "spf_softfail")
    elif spf in ("NONE", "?"):
        _add(anomalies, "faible", "SPF NONE : aucun enregistrement SPF configuré", scores, "spf_none")

    if dkim == "FAIL":
        _add(anomalies, "haute", "DKIM FAIL : signature du mail invalide", scores, "dkim_fail")
    elif dkim in ("NONE", "?"):
        _add(anomalies, "faible", "DKIM NONE : aucune signature DKIM", scores, "dkim_none")

    if dmarc == "FAIL":
        _add(anomalies, "haute", "DMARC FAIL : politique du domaine rejette ce mail", scores, "dmarc_fail")
    elif dmarc in ("NONE", "?"):
        _add(anomalies, "faible", "DMARC NONE : aucune politique DMARC", scores, "dmarc_none")

    return anomalies
