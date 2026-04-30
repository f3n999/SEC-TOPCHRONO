"""
Parser EML local — V5
Utilise eml-parser (GOVCERT-LU) pour extraire toutes les informations
d'un fichier .eml sans passer par Outlook ou Graph API.
"""
import re
from pathlib import Path

try:
    import eml_parser as _eml_parser
    _EML_PARSER_AVAILABLE = True
except ImportError:
    _EML_PARSER_AVAILABLE = False

# Fallback : stdlib email si eml-parser pas installé
import email as _stdlib_email
from email import policy as _email_policy


def parse_eml(path: Path) -> dict:
    """
    Parse un fichier .eml et retourne un dict normalisé
    compatible avec le moteur de détection V5.
    """
    raw = path.read_bytes()

    if _EML_PARSER_AVAILABLE:
        return _parse_with_eml_parser(raw)
    else:
        return _parse_with_stdlib(raw)


# ─── Parser principal : eml-parser (GOVCERT-LU) ───────────────────────────────

def _parse_with_eml_parser(raw: bytes) -> dict:
    ep = _eml_parser.EmlParser(
        include_raw_body=True,
        include_attachment_data=False,
    )
    parsed = ep.decode_email_bytes(raw)

    header = parsed.get("header", {})
    raw_headers = header.get("header", {})

    expediteur = _extract_address(header.get("from", ""))
    sujet = header.get("subject", "")

    # Corps texte + HTML
    corps_text, corps_html = "", ""
    urls = []
    for part in parsed.get("body", []):
        ct = part.get("content_type", "")
        content = part.get("content", "")
        if "html" in ct:
            corps_html += content
        else:
            corps_text += content
        # eml-parser extrait déjà les URLs
        urls.extend(part.get("uri", []))

    # Pièces jointes
    pieces_jointes = [
        att.get("filename", "") or att.get("name", "")
        for att in parsed.get("attachment", [])
    ]

    # SPF / DKIM / DMARC depuis Authentication-Results
    auth_results = " ".join(raw_headers.get("authentication-results", []))
    received_spf = " ".join(raw_headers.get("received-spf", []))
    spf = _extract_auth_result(auth_results, "spf") or _extract_spf_from_received(received_spf)
    dkim = _extract_auth_result(auth_results, "dkim")
    dmarc = _extract_auth_result(auth_results, "dmarc")

    # Reply-To
    reply_to_raw = raw_headers.get("reply-to", [])
    reply_to = _extract_address(reply_to_raw[0] if reply_to_raw else "")

    # Date
    date_obj = header.get("date")
    date_str = date_obj.isoformat() if date_obj else ""

    return {
        "expediteur": expediteur,
        "sujet": sujet,
        "date": date_str,
        "corps": corps_text,
        "corps_html": corps_html,
        "urls": list(set(urls)),
        "pieces_jointes": [p for p in pieces_jointes if p],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "reply_to": reply_to,
        "message_id": _flatten(raw_headers.get("message-id", "")),
    }


# ─── Fallback : stdlib email ───────────────────────────────────────────────────

def _parse_with_stdlib(raw: bytes) -> dict:
    msg = _stdlib_email.message_from_bytes(raw, policy=_email_policy.default)

    expediteur = _extract_address(msg.get("From", ""))
    sujet = msg.get("Subject", "")
    reply_to = _extract_address(msg.get("Reply-To", ""))
    date_str = msg.get("Date", "")

    corps_text, corps_html = "", ""
    pieces_jointes = []

    for part in msg.walk():
        ct = part.get_content_type()
        cd = part.get_content_disposition() or ""

        if "attachment" in cd:
            fname = part.get_filename() or ""
            if fname:
                pieces_jointes.append(fname)
            continue

        if ct == "text/plain":
            try:
                corps_text += part.get_content()
            except Exception:
                pass
        elif ct == "text/html":
            try:
                corps_html += part.get_content()
            except Exception:
                pass

    # Extraire URLs depuis le texte brut
    full_text = f"{corps_text} {corps_html}"
    urls = list(set(re.findall(r"https?://[^\s<>\"')\]]+", full_text, re.IGNORECASE)))

    # Auth headers
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")
    spf = _extract_auth_result(auth_results, "spf") or _extract_spf_from_received(received_spf)
    dkim = _extract_auth_result(auth_results, "dkim")
    dmarc = _extract_auth_result(auth_results, "dmarc")

    return {
        "expediteur": expediteur,
        "sujet": sujet,
        "date": date_str,
        "corps": corps_text,
        "corps_html": corps_html,
        "urls": urls,
        "pieces_jointes": pieces_jointes,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "reply_to": reply_to,
        "message_id": msg.get("Message-ID", ""),
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _extract_address(value: str) -> str:
    """Extrait l'adresse email d'un champ From/Reply-To."""
    if not value:
        return ""
    match = re.search(r"[\w.+\-]+@[\w.\-]+", value)
    return match.group(0).lower() if match else value.lower().strip()


def _extract_auth_result(header_value: str, protocol: str) -> str:
    """Extrait le résultat SPF/DKIM/DMARC depuis Authentication-Results."""
    if not header_value:
        return "?"
    pattern = rf"{protocol}\s*=\s*(\w+)"
    match = re.search(pattern, header_value, re.IGNORECASE)
    return match.group(1).upper() if match else "?"


def _extract_spf_from_received(received_spf: str) -> str:
    """Extrait le résultat depuis l'en-tête Received-SPF."""
    if not received_spf:
        return "?"
    match = re.match(r"\s*(\w+)", received_spf)
    return match.group(1).upper() if match else "?"


def _flatten(value) -> str:
    if isinstance(value, list):
        return value[0] if value else ""
    return value or ""
