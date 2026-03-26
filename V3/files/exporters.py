"""
Module d'export des resultats - v2.1
Supporte : console, JSON, CSV, envoi au serveur (API REST).
"""
import json
import csv
import os
import requests
from datetime import datetime


SERVER_URL = os.environ.get("PHISHING_SERVER", "http://192.168.237.133:8000")


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
    """Exporte les resultats en CSV compatible Excel."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(dossier, f'scan_{timestamp}.csv')

    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow([
            'Boite', 'Date reception', 'Expediteur', 'Sujet',
            'SPF', 'DKIM', 'DMARC', 'Reply-To mismatch',
            'Score', 'Niveau', 'Action', 'Anomalies'
        ])
        for r in resultats:
            anomalies_str = ' | '.join(
                f"[{a['severite']}] {a['description']}" for a in r.get('anomalies', [])
            )
            writer.writerow([
                r.get('boite', ''),
                r.get('date', ''),
                r.get('expediteur', ''),
                r.get('sujet', ''),
                r.get('spf', '?'),
                r.get('dkim', '?'),
                r.get('dmarc', '?'),
                'OUI' if r.get('reply_to_mismatch') else 'NON',
                r.get('score', 0),
                r.get('niveau', '?'),
                r.get('action', '?'),
                anomalies_str
            ])

    return filename


def envoyer_au_serveur(resultats: list, agent_id: str = "agent-windows") -> dict:
    """Envoie les resultats au serveur Linux via l'API REST."""
    url = f"{SERVER_URL}/api/scan"

    payload = {
        "agent_id": agent_id,
        "scan_date": datetime.now().isoformat(),
        "results": resultats
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f'  [SERVEUR] Envoye avec succes ! Scan ID: {data.get("scan_id")}')
            print(f'            {data.get("total_stored")} resultats stockes en base.')
            return data
        else:
            print(f'  [SERVEUR] Erreur HTTP {response.status_code}: {response.text[:100]}')
            return {"status": "error", "code": response.status_code}
    except requests.exceptions.ConnectionError:
        print(f'  [SERVEUR] Connexion impossible a {SERVER_URL}')
        print(f'            Le serveur est-il demarre ?')
        return {"status": "connection_error"}
    except Exception as e:
        print(f'  [SERVEUR] Erreur: {e}')
        return {"status": "error", "detail": str(e)}


def exporter_rapport(resultats: list, dossier: str = '.') -> dict:
    """Export complet : console + CSV + JSON + envoi serveur."""
    exporter_console(resultats)

    json_path = exporter_json(resultats, dossier)
    csv_path = exporter_csv(resultats, dossier)

    print(f'  [EXPORT] JSON : {json_path}')
    print(f'  [EXPORT] CSV  : {csv_path}')

    # Envoi au serveur
    print(f'  [EXPORT] Envoi au serveur ({SERVER_URL})...')
    server_response = envoyer_au_serveur(resultats)

    print()
    return {"json": json_path, "csv": csv_path, "server": server_response}
