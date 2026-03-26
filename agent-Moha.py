import asyncio
import configparser
import sys
import io

# Forcer l'encodage UTF-8 pour la console Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='replace')

from graph import Graph


async def display_access_token(graph: Graph):
    """Affiche le token d'acces app-only."""
    token = await graph.get_app_only_token()
    print(f'\n[OK] Token obtenu avec succes !')
    print(f'     (longueur: {len(token)} caracteres)')
    print(f'     Debut: {token[:50]}...\n')


async def list_users(graph: Graph):
    """Affiche la liste des utilisateurs du tenant."""
    try:
        users_page = await graph.list_users()
    except Exception as e:
        print(f'\n[ERREUR] Impossible de lister les utilisateurs.')
        print(f'  Detail: {e}')
        print(f'  --> Verifie que la permission User.Read.All (Application) est accordee dans Azure.\n')
        return None

    if users_page and users_page.value:
        print(f'\n[LISTE] {len(users_page.value)} utilisateur(s) dans le tenant :\n')
        for i, user in enumerate(users_page.value):
            upn = user.user_principal_name or "N/A"
            mail = user.mail or "pas de mail"
            print(f'  {i + 1}. {user.display_name or "N/A"}')
            print(f'     UPN  : {upn}')
            print(f'     Mail : {mail}')
            print(f'     ID   : {user.id}')
            print()
        return users_page.value
    else:
        print('\n[!] Aucun utilisateur trouve.\n')
        return None


async def list_emails(graph: Graph):
    """Affiche les derniers mails d'un utilisateur du tenant."""
    # D'abord lister les users pour choisir
    print('\n[INFO] Chargement des utilisateurs du tenant...')
    
    try:
        users_page = await graph.list_users()
    except Exception as e:
        print(f'\n[ERREUR] Impossible de lister les utilisateurs.')
        print(f'  Detail: {e}')
        print(f'  --> Verifie que la permission User.Read.All (Application) est accordee.\n')
        return

    if not users_page or not users_page.value:
        print('[!] Aucun utilisateur trouve dans le tenant.')
        return

    # Afficher les users disponibles
    users = users_page.value
    print(f'\n[USERS] {len(users)} utilisateur(s) disponible(s) :\n')
    for i, user in enumerate(users):
        upn = user.user_principal_name or "?"
        name = user.display_name or "?"
        print(f'  {i + 1}. {name} ({upn})')

    # Choisir un user
    try:
        choix = int(input('\n> Numero de l\'utilisateur a scanner : ')) - 1
        if choix < 0 or choix >= len(users):
            print('[X] Numero hors limites.')
            return
        user = users[choix]
    except ValueError:
        print('[X] Choix invalide.')
        return

    # Utiliser le userPrincipalName ou l'ID pour acceder aux mails
    user_identifier = user.user_principal_name or user.id
    user_name = user.display_name or user_identifier
    
    print(f'\n[SCAN] Recuperation des 10 derniers mails de {user_name}...')
    print(f'       (identifiant utilise: {user_identifier})\n')

    try:
        messages = await graph.list_user_messages(user_identifier, top=10)
    except Exception as e:
        error_str = str(e)
        print(f'[ERREUR] Impossible de lire les mails de {user_name}.')
        
        if "401" in error_str:
            print('  --> Erreur 401: Token non autorise.')
            print('  --> Verifie que Mail.Read (Application) est accorde dans Azure.')
        elif "403" in error_str:
            print('  --> Erreur 403: Acces refuse.')
            print('  --> Verifie les permissions API et le consentement admin.')
        elif "404" in error_str:
            print('  --> Erreur 404: Boite mail introuvable.')
            print('  --> Cet utilisateur n\'a peut-etre pas de boite Exchange Online.')
        else:
            print(f'  --> Detail: {e}')
        print()
        return

    if not messages or not messages.value:
        print(f'[!] Aucun mail trouve dans la boite de {user_name}.')
        print('    --> Envoie un mail de test a cet utilisateur et reessaie.\n')
        return

    print(f'[OK] {len(messages.value)} mail(s) recupere(s) :\n')
    print('=' * 70)

    for m in messages.value:
        # Expediteur
        sender = "inconnu"
        if m.from_ and m.from_.email_address:
            sender = m.from_.email_address.address

        # Date
        date_str = str(m.received_date_time) if m.received_date_time else "?"
        date = date_str[:16]

        # Sujet
        subject = m.subject or "(sans sujet)"

        # Headers d'authentification
        spf = dkim = dmarc = "?"
        reply_to = ""
        auth_header_found = False

        if m.internet_message_headers:
            for header in m.internet_message_headers:
                name = (header.name or "").lower()
                value = header.value or ""

                if name == "authentication-results":
                    auth_header_found = True
                    val_lower = value.lower()

                    # SPF
                    if "spf=pass" in val_lower:
                        spf = "PASS"
                    elif "spf=softfail" in val_lower:
                        spf = "SOFTFAIL"
                    elif "spf=fail" in val_lower:
                        spf = "FAIL"
                    elif "spf=none" in val_lower:
                        spf = "NONE"

                    # DKIM
                    if "dkim=pass" in val_lower:
                        dkim = "PASS"
                    elif "dkim=fail" in val_lower:
                        dkim = "FAIL"
                    elif "dkim=none" in val_lower:
                        dkim = "NONE"

                    # DMARC
                    if "dmarc=pass" in val_lower:
                        dmarc = "PASS"
                    elif "dmarc=fail" in val_lower:
                        dmarc = "FAIL"
                    elif "dmarc=none" in val_lower:
                        dmarc = "NONE"

                elif name == "reply-to":
                    reply_to = value

        # Affichage
        print(f'  Date    : {date}')
        print(f'  De      : {sender}')
        print(f'  Sujet   : {subject}')
        print(f'  SPF     : {spf}')
        print(f'  DKIM    : {dkim}')
        print(f'  DMARC   : {dmarc}')
        if reply_to and reply_to.lower() != sender.lower():
            print(f'  Reply-To: {reply_to} [DIFFERENT DU FROM]')
        if not auth_header_found:
            print(f'  [!] Header Authentication-Results non trouve')
        print('-' * 70)

    print()


async def main():
    print('=' * 50)
    print('  PHISHING DETECTION AGENT v1.0')
    print('  Microsoft Graph API - App Only')
    print('=' * 50)
    print()

    # Charger la configuration
    config = configparser.ConfigParser()
    config.read(['config.cfg', 'config.dev.cfg'])
    
    if 'azure' not in config:
        print('[ERREUR] Fichier config.cfg introuvable ou section [azure] manquante.')
        print('         Assurez-vous que config.cfg est dans le meme repertoire.')
        return

    azure_settings = config['azure']

    # Verifier les cles requises
    required_keys = ['clientId', 'clientSecret', 'tenantId']
    for key in required_keys:
        if key not in azure_settings:
            print(f'[ERREUR] Cle manquante dans config.cfg : {key}')
            return

    # Initialiser le client Graph
    graph = Graph(azure_settings)
    print('[OK] Client Graph initialise.\n')

    choice = -1

    while choice != 0:
        print('+--------------------------------------------+')
        print('|  MENU PRINCIPAL                            |')
        print('+--------------------------------------------+')
        print('|  1. Verifier le token d\'acces              |')
        print('|  2. Lister les utilisateurs du tenant      |')
        print('|  3. Scanner les mails d\'un utilisateur     |')
        print('|  0. Quitter                                |')
        print('+--------------------------------------------+')

        try:
            choice = int(input('\n> Votre choix : '))
        except ValueError:
            choice = -1

        if choice == 0:
            print('\n[FIN] Agent arrete. A bientot !\n')
        elif choice == 1:
            await display_access_token(graph)
        elif choice == 2:
            await list_users(graph)
        elif choice == 3:
            await list_emails(graph)
        else:
            print('\n[X] Choix invalide, reessayez.\n')


if __name__ == '__main__':
    asyncio.run(main())