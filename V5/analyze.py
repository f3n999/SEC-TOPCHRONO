#!/usr/bin/env python3
"""
V5 — Analyseur de phishing local (.eml)
Usage :
  python analyze.py                  → demande le fichier interactivement
  python analyze.py mail.eml         → analyse complète (VT + URLScan inclus)
  python analyze.py mail.eml --json  → export JSON dans le terminal
  python analyze.py mail.eml --save  → sauvegarde le rapport JSON dans reports/
"""
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from src.parser.eml_parser import parse_eml
from src.detection.engine import DetectionEngine
from src.scoring.risk_scorer import score_email
from src.report import print_report
from src.options.virustotal import check_virustotal
from src.options.urlscan import check_urlscan

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config" / "rules.yaml"
REPORTS_DIR = BASE_DIR / "reports"

# On ne scanne que les URLs hors domaines d'infra évidents
_SKIP_SCAN_DOMAINS = {
    "microsoft.com", "outlook.com", "office.com", "google.com",
    "w3.org", "schema.org", "star-transport.fr",
}


def get_eml_path(args_path: str | None) -> Path:
    if args_path:
        p = Path(args_path.strip('"').strip("'"))
    else:
        raw = input("\n  Chemin du fichier .eml (ou glisser-déposer) : ").strip().strip('"').strip("'")
        p = Path(raw)
    if not p.exists():
        print(f"\n  Fichier introuvable : {p}")
        sys.exit(1)
    return p


def _urls_a_scanner(urls: list[str], niveau: str) -> list[str]:
    """Retourne les URLs à envoyer à VT/URLScan (uniquement si MEDIUM ou HIGH)."""
    if niveau == "LOW":
        return []
    suspects = []
    for url in urls:
        skip = any(d in url.lower() for d in _SKIP_SCAN_DOMAINS)
        if not skip:
            suspects.append(url)
    return suspects[:5]  # max 5 pour préserver le quota


def run_external_checks(email_data: dict, result: dict, console_output: bool = True) -> dict:
    """Lance VT + URLScan sur les URLs suspectes. Retourne les résultats combinés."""
    urls = _urls_a_scanner(email_data.get("urls", []), result["niveau"])
    ext_results = {"virustotal": {}, "urlscan": {}}

    if not urls:
        if console_output:
            print("  [VT/URLScan] Aucune URL suspecte à scanner.")
        return ext_results

    if console_output:
        print(f"\n  Vérification externe de {len(urls)} URL(s) suspecte(s)...")

    # VirusTotal
    if console_output:
        print("  [VirusTotal] En cours...")
    vt = check_virustotal(urls)
    ext_results["virustotal"] = vt
    if console_output:
        for url, r in vt.items():
            flag = "🔴 MALVEILLANT" if r.get("malicious", 0) > 0 else ("🟡 SUSPECT" if r.get("suspicious", 0) > 0 else "🟢 OK")
            print(f"    {flag}  {url[:65]}")
            if r.get("note"):
                print(f"           → {r['note']}")

    # URLScan
    if console_output:
        print("  [URLScan.io] Soumission + attente résultat (~60s)...")
    us = check_urlscan(urls)
    ext_results["urlscan"] = us
    if console_output:
        for url, r in us.items():
            verdict = r.get("verdict", "?")
            flag = "🔴 MALVEILLANT" if verdict == "MALVEILLANT" else ("⏳ " + verdict if verdict in ("submitted", "timeout") else "🟢 OK")
            print(f"    {flag}  {url[:65]}")
            if r.get("report_url"):
                print(f"           → Rapport : {r['report_url']}")

    return ext_results


def export_json(email_data: dict, anomalies: list, result: dict, ext_results: dict, save: bool):
    output = {
        "timestamp": datetime.now().isoformat(),
        "email": {
            "expediteur": email_data.get("expediteur"),
            "sujet": email_data.get("sujet"),
            "date": email_data.get("date"),
            "spf": email_data.get("spf"),
            "dkim": email_data.get("dkim"),
            "dmarc": email_data.get("dmarc"),
            "urls": email_data.get("urls", []),
            "pieces_jointes": email_data.get("pieces_jointes", []),
        },
        "resultat": result,
        "anomalies": [a for a in anomalies if a.get("rule") != "whitelist_bonus"],
        "verifications_externes": ext_results,
    }
    json_str = json.dumps(output, ensure_ascii=False, indent=2)
    print(json_str)
    if save:
        REPORTS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = REPORTS_DIR / f"report_{ts}.json"
        out_file.write_text(json_str, encoding="utf-8")
        print(f"\n  Rapport sauvegardé : {out_file}")


def main():
    parser = argparse.ArgumentParser(description="V5 — Analyseur de phishing local (.eml)")
    parser.add_argument("fichier", nargs="?", help="Chemin vers le fichier .eml")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Afficher le résultat en JSON")
    parser.add_argument("--save", action="store_true", help="Sauvegarder le rapport JSON dans reports/")
    args = parser.parse_args()

    print("\n  ╔══════════════════════════════════════╗")
    print("  ║   Analyseur Phishing V5 — TopChrono  ║")
    print("  ╚══════════════════════════════════════╝")

    eml_path = get_eml_path(args.fichier)
    print(f"\n  Analyse de : {eml_path.name}\n")

    # 1. Parse EML
    email_data = parse_eml(eml_path)

    # 2. Détection locale
    engine = DetectionEngine(rules_file=str(CONFIG_FILE))
    anomalies = engine.analyser(email_data)

    # 3. Score
    result = score_email(anomalies)

    # 4. Rapport local
    if not args.json_out:
        print_report(email_data, anomalies, result)

    # 5. Vérifications externes (VT + URLScan) — toujours actives
    ext_results = run_external_checks(email_data, result, console_output=not args.json_out)

    # 6. Export JSON si demandé
    if args.json_out or args.save:
        export_json(email_data, anomalies, result, ext_results, args.save)


if __name__ == "__main__":
    main()
