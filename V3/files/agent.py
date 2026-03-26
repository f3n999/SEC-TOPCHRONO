"""
PHISHING DETECTION AGENT v2.0
Scan des boites mail via Microsoft Graph API + Moteur heuristique + Rapport.
"""
import asyncio
import configparser
import sys
import io
import os

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='replace')

from graph import Graph
from detection_rules import detecter_anomalies
from risk_scorer import score_email
from exporters import exporter_rapport


def parse_auth_headers(internet_message_headers):
    spf = dkim = dmarc = "?"
    reply_to = ""
    if not internet_message_headers:
        return spf, dkim, dmarc, reply_to
    for header in internet_message_headers:
        name = (header.name or "").lower()
        value = header.value or ""
        if name == "authentication-results":
            val = value.lower()
            if "spf=pass" in val: spf = "PASS"
            elif "spf=softfail" in val: spf = "SOFTFAIL"
            elif "spf=fail" in val: spf = "FAIL"
            elif "spf=none" in val: spf = "NONE"
            if "dkim=pass" in val: dkim = "PASS"
            elif "dkim=fail" in val: dkim = "FAIL"
            elif "dkim=none" in val: dkim = "NONE"
            if "dmarc=pass" in val: dmarc = "PASS"
            elif "dmarc=fail" in val: dmarc = "FAIL"
            elif "dmarc=none" in val: dmarc = "NONE"
        elif name == "reply-to":
            reply_to = value
    return spf, dkim, dmarc, reply_to


def graph_message_to_dict(message):
    sender = ""
    if message.from_ and message.from_.email_address:
        sender = message.from_.email_address.address or ""
    subject = message.subject or ""
    date = str(message.received_date_time)[:16] if message.received_date_time else "?"
    spf, dkim, dmarc, reply_to = parse_auth_headers(message.internet_message_headers)
    
    corps = ""
    corps_html = ""
    if message.body and message.body.content:
        # Le contenu peut etre text ou html
        if message.body.content_type and str(message.body.content_type.value).lower() == 'html':
            corps_html = message.body.content
            corps = message.body.content # On met aussi dans corps pour la regex simple
        else:
            corps = message.body.content

    pieces_jointes = []
    if message.attachments:
        for att in message.attachments:
            pieces_jointes.append(att.name or "")

    return {
        "expediteur": sender, "sujet": subject, "date": date,
        "reply_to": reply_to, "corps": corps, "corps_html": corps_html,
        "urls": [], "pieces_jointes": pieces_jointes,
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
    }


async def display_access_token(graph: Graph):
    token = await graph.get_app_only_token()
    print(f'\n[OK] Token obtenu ({len(token)} caracteres)')
    print(f'     Debut: {token[:50]}...\n')


async def list_users(graph: Graph):
    try:
        users_page = await graph.list_users()
    except Exception as e:
        print(f'\n[ERREUR] {e}')
        print(f'  --> Verifie User.Read.All (Application) dans Azure.\n')
        return None
    if users_page and users_page.value:
        print(f'\n[LISTE] {len(users_page.value)} utilisateur(s) :\n')
        for i, user in enumerate(users_page.value):
            print(f'  {i+1}. {user.display_name or "N/A"}')
            print(f'     UPN : {user.user_principal_name or "N/A"}')
            print(f'     Mail: {user.mail or "N/A"}')
            print(f'     ID  : {user.id}\n')
        return users_page.value
    print('\n[!] Aucun utilisateur.\n')
    return None


async def quick_scan(graph: Graph):
    """Scan rapide : 10 mails d'un user avec analyse inline."""
    print('\n[INFO] Chargement des utilisateurs...')
    try:
        users_page = await graph.list_users()
    except Exception as e:
        print(f'[ERREUR] {e}')
        return
    if not users_page or not users_page.value:
        print('[!] Aucun utilisateur.')
        return

    users = users_page.value
    print(f'\n[USERS] {len(users)} utilisateur(s) :\n')
    for i, u in enumerate(users):
        print(f'  {i+1}. {u.display_name or "?"} ({u.user_principal_name or "?"})')

    try:
        choix = int(input('\n> Numero : ')) - 1
        user = users[choix]
    except (ValueError, IndexError):
        print('[X] Invalide.')
        return

    uid = user.user_principal_name or user.id
    print(f'\n[SCAN] Analyse des 10 derniers mails de {user.display_name}...\n')

    try:
        messages = await graph.list_user_messages(uid, top=10)
    except Exception as e:
        print(f'[ERREUR] {e}\n')
        return
    if not messages or not messages.value:
        print('[!] Aucun mail.\n')
        return

    print('=' * 70)
    for m in messages.value:
        data = graph_message_to_dict(m)
        anomalies = detecter_anomalies(data)
        ev = score_email(anomalies)

        if ev['niveau'] == 'HIGH':
            tag = '[!!!] PHISHING'
        elif ev['niveau'] == 'MEDIUM':
            tag = '[ ! ] SUSPECT '
        else:
            tag = '[ OK] LEGITIME'

        print(f'  {tag} | Score: {ev["score"]}/100')
        print(f'  Date  : {data["date"]}')
        print(f'  De    : {data["expediteur"]}')
        print(f'  Sujet : {data["sujet"][:55]}')
        print(f'  SPF: {data["spf"]} | DKIM: {data["dkim"]} | DMARC: {data["dmarc"]}')
        for a in anomalies:
            print(f'    -> [{a["severite"]}] {a["description"][:60]}')
        print('-' * 70)
    print()


async def full_scan(graph: Graph):
    """Scan complet : tous les mails, tous les users, export CSV/JSON."""
    print('\n[1/5] Chargement des utilisateurs...')
    try:
        users_page = await graph.list_users()
    except Exception as e:
        print(f'[ERREUR] {e}')
        return
    if not users_page or not users_page.value:
        print('[!] Aucun utilisateur.')
        return

    users = users_page.value
    print(f'[OK] {len(users)} utilisateur(s).\n')
    for i, u in enumerate(users):
        print(f'  {i+1}. {u.display_name or "?"} ({u.user_principal_name or "?"})')
    print(f'  0. Scanner TOUS')

    try:
        choix = int(input('\n> Numero (0=tous) : '))
    except ValueError:
        print('[X] Invalide.')
        return

    if choix == 0:
        to_scan = users
    elif 1 <= choix <= len(users):
        to_scan = [users[choix - 1]]
    else:
        print('[X] Hors limites.')
        return

    try:
        nb = int(input('> Mails par boite (defaut 25) : ') or '25')
    except ValueError:
        nb = 25

    print(f'\n[2/5] Scan de {len(to_scan)} boite(s)...')
    all_results = []

    for user in to_scan:
        uid = user.user_principal_name or user.id
        name = user.display_name or uid
        print(f'\n  Scan de {name}...')

        try:
            messages = await graph.list_user_messages(uid, top=nb)
        except Exception as e:
            err = str(e)
            if "404" in err or "401" in err:
                print(f'    [!] Boite inaccessible (licence Exchange manquante ?). Skip.')
            else:
                print(f'    [!] Erreur: {e}')
            continue

        if not messages or not messages.value:
            print(f'    [!] Aucun mail.')
            continue

        print(f'    [OK] {len(messages.value)} mail(s).')

        for m in messages.value:
            data = graph_message_to_dict(m)
            anomalies = detecter_anomalies(data)
            ev = score_email(anomalies)

            all_results.append({
                "boite": name,
                "date": data["date"],
                "expediteur": data["expediteur"],
                "sujet": data["sujet"],
                "spf": data["spf"],
                "dkim": data["dkim"],
                "dmarc": data["dmarc"],
                "reply_to_mismatch": bool(data["reply_to"] and
                    data["reply_to"].lower() != data["expediteur"].lower()),
                "score": ev["score"],
                "niveau": ev["niveau"],
                "action": ev["action"],
                "anomalies": anomalies,
            })

    if not all_results:
        print('\n[!] Aucun mail analyse.\n')
        return

    print(f'\n[3/5] {len(all_results)} mails analyses.')
    print('[4/5] Generation des rapports...')
    paths = exporter_rapport(all_results)
    print('[5/5] Termine !\n')


async def main():
    print('=' * 55)
    print('  PHISHING DETECTION AGENT v2.0')
    print('  Microsoft Graph API + Moteur Heuristique')
    print('=' * 55)
    print()

    config = configparser.ConfigParser()
    # Le fichier de conf est a la racine (dossier parent)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_paths = [
        os.path.join(base_dir, 'config.cfg'), 
        os.path.join(base_dir, 'config.dev.cfg'),
        'config.cfg' # fallback
    ]
    config.read(config_paths)
    if 'azure' not in config:
        print('[ERREUR] config.cfg manquant.')
        return

    azure_settings = config['azure']
    for key in ['clientId', 'clientSecret', 'tenantId']:
        if key not in azure_settings:
            print(f'[ERREUR] Cle manquante : {key}')
            return

    graph = Graph(azure_settings)
    print('[OK] Client Graph initialise.\n')

    choice = -1
    while choice != 0:
        print('+----------------------------------------------+')
        print('|  MENU PRINCIPAL                              |')
        print('+----------------------------------------------+')
        print('|  1. Verifier le token                        |')
        print('|  2. Lister les utilisateurs                  |')
        print('|  3. Scan rapide (10 mails, 1 user)           |')
        print('|  4. Scan complet + Rapport (CSV/JSON)        |')
        print('|  0. Quitter                                  |')
        print('+----------------------------------------------+')
        try:
            choice = int(input('\n> Choix : '))
        except ValueError:
            choice = -1

        if choice == 0:
            print('\n[FIN] Agent arrete.\n')
        elif choice == 1:
            await display_access_token(graph)
        elif choice == 2:
            await list_users(graph)
        elif choice == 3:
            await quick_scan(graph)
        elif choice == 4:
            await full_scan(graph)
        else:
            print('\n[X] Invalide.\n')

if __name__ == '__main__':
    asyncio.run(main())
