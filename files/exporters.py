"""
Module d'export des resultats - v2.0
Supporte : console, JSON, CSV.
"""
import json
import csv
import os
from datetime import datetime


def exporter_console(resultats: list):
    """Affiche les resultats dans la console."""
    total = len(resultats)
    phishing = [r for r in resultats if r['niveau'] == 'HIGH']
    suspects = [r for r in resultats if r['niveau'] == 'MEDIUM']
    legitimes = [r for r in resultats if r['niveau'] == 'LOW']

    print('\n' + '=' * 70)
    print('  RAPPORT D\'ANALYSE - PHISHING DETECTION AGENT v2.0')
    print('=' * 70)
    print(f'  Date du scan     : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'  Emails analyses  : {total}')
    print(f'  Phishing (HIGH)  : {len(phishing)}')
    print(f'  Suspects (MEDIUM): {len(suspects)}')
    print(f'  Legitimes (LOW)  : {len(legitimes)}')
    if total > 0:
        print(f'  Taux de detection: {(len(phishing) + len(suspects)) / total * 100:.1f}%')
    print('=' * 70)

    # Details des emails flagges
    flagged = [r for r in resultats if r['niveau'] in ('HIGH', 'MEDIUM')]
    if flagged:
        print(f'\n  EMAILS FLAGGES ({len(flagged)}) :')
        print('-' * 70)
        for r in flagged:
            print(f'  [{r["niveau"]:6}] Score: {r["score"]:3}/100 | De: {r["expediteur"][:35]}')
            print(f'          Sujet: {r["sujet"][:55]}')
            if r.get('anomalies'):
                for a in r['anomalies']:
                    print(f'          -> [{a["severite"]}] {a["description"][:60]}')
            print()
    else:
        print('\n  Aucun email suspect detecte.\n')


def exporter_json(resultats: list, dossier: str = '.') -> str:
    """Exporte les resultats en JSON."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(dossier, f'scan_{timestamp}.json')

    total = len(resultats)
    phishing = len([r for r in resultats if r['niveau'] == 'HIGH'])
    suspects = len([r for r in resultats if r['niveau'] == 'MEDIUM'])

    rapport = {
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total_emails": total,
            "phishing_high": phishing,
            "suspects_medium": suspects,
            "legitimes_low": total - phishing - suspects,
            "detection_rate": f"{(phishing + suspects) / max(total, 1) * 100:.1f}%"
        },
        "details": resultats
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False, default=str)

    return filename


def exporter_csv(resultats: list, dossier: str = '.') -> str:
    """Exporte les resultats en CSV (ouvrable dans Excel)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(dossier, f'scan_{timestamp}.csv')

    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f, delimiter=';')

        # En-tete
        writer.writerow([
            'Date reception', 'Expediteur', 'Sujet',
            'SPF', 'DKIM', 'DMARC', 'Reply-To mismatch',
            'Score', 'Niveau', 'Action', 'Anomalies'
        ])

        # Lignes
        for r in resultats:
            reply_to_mismatch = 'OUI' if r.get('reply_to_mismatch') else 'NON'
            anomalies_str = ' | '.join(
                f"[{a['severite']}] {a['description']}" for a in r.get('anomalies', [])
            )
            writer.writerow([
                r.get('date', ''),
                r.get('expediteur', ''),
                r.get('sujet', ''),
                r.get('spf', '?'),
                r.get('dkim', '?'),
                r.get('dmarc', '?'),
                reply_to_mismatch,
                r.get('score', 0),
                r.get('niveau', '?'),
                r.get('action', '?'),
                anomalies_str
            ])

    return filename


def exporter_rapport(resultats: list, dossier: str = '.') -> dict:
    """Exporte dans tous les formats et retourne les chemins."""
    exporter_console(resultats)
    json_path = exporter_json(resultats, dossier)
    csv_path = exporter_csv(resultats, dossier)

    print(f'  [EXPORT] JSON : {json_path}')
    print(f'  [EXPORT] CSV  : {csv_path}')
    print()

    return {"json": json_path, "csv": csv_path}
