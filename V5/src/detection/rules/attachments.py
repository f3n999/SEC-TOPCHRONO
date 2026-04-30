"""Vérification des pièces jointes."""
import re


def _add(anomalies, severite, description, scores, rule):
    anomalies.append({
        "severite": severite,
        "description": description,
        "score": scores.get(severite, 0),
        "rule": rule,
    })


def check_attachments(email_data: dict, rules: dict, scores: dict) -> list[dict]:
    anomalies = []
    pj = email_data.get("pieces_jointes", [])
    dangerous_ext = set(rules.get("dangerous_extensions", [
        ".exe", ".bat", ".scr", ".vbs", ".js", ".ps1", ".cmd", ".msi", ".hta",
    ]))
    double_ext_pattern = re.compile(r"\.\w+\.\w+$")

    for fichier in pj:
        nom = fichier if isinstance(fichier, str) else fichier.get("name", "")
        if not nom:
            continue
        ext = "." + nom.rsplit(".", 1)[-1].lower() if "." in nom else ""

        if ext in dangerous_ext:
            _add(anomalies, "haute", f"Pièce jointe dangereuse : {nom}", scores, "dangerous_attachment")
        if double_ext_pattern.search(nom):
            _add(anomalies, "haute", f"Double extension suspecte : {nom}", scores, "double_extension")

    return anomalies
