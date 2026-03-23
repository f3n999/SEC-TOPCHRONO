"""
Moteur de detection heuristique - v2.0
Adapte pour fonctionner avec les donnees Microsoft Graph API.
Ajoute : verification SPF/DKIM/DMARC depuis les headers d'authentification.
"""
import re

SCORES = {'haute': 40, 'moyenne': 20, 'faible': 5}


class MoteurDetection:

    def __init__(self):
        self.anomalies = []

    def analyser_email(self, donnees_email: dict) -> list:
        """Analyse un email et retourne la liste des anomalies detectees.
        
        Attend un dict avec les cles :
            - expediteur (str)
            - sujet (str)
            - reply_to (str)
            - urls (list[str])
            - corps (str)
            - corps_html (str)
            - spf (str) : PASS/FAIL/SOFTFAIL/NONE/?
            - dkim (str) : PASS/FAIL/NONE/?
            - dmarc (str) : PASS/FAIL/NONE/?
        """
        self.anomalies = []
        self._verifier_auth_headers(donnees_email)
        self._verifier_expediteur(donnees_email)
        self._detecter_urls_suspectes(donnees_email)
        self._detecter_mots_cles_phishing(donnees_email)
        self._verifier_pieces_jointes(donnees_email)
        return self.anomalies

    def _ajouter_anomalie(self, severite: str, description: str):
        self.anomalies.append({
            'severite': severite,
            'description': description,
            'score': SCORES.get(severite, 0)
        })

    # ── NOUVEAU : Verification SPF / DKIM / DMARC ──
    def _verifier_auth_headers(self, donnees: dict):
        """Verifie les resultats d'authentification email (SPF, DKIM, DMARC)."""
        spf = donnees.get('spf', '?').upper()
        dkim = donnees.get('dkim', '?').upper()
        dmarc = donnees.get('dmarc', '?').upper()

        # SPF
        if spf == 'FAIL':
            self._ajouter_anomalie('haute',
                f"SPF FAIL : le serveur expediteur n'est pas autorise par le domaine")
        elif spf == 'SOFTFAIL':
            self._ajouter_anomalie('moyenne',
                f"SPF SOFTFAIL : le serveur expediteur est probablement non autorise")
        elif spf == 'NONE':
            self._ajouter_anomalie('faible',
                f"SPF NONE : aucun enregistrement SPF configure pour ce domaine")

        # DKIM
        if dkim == 'FAIL':
            self._ajouter_anomalie('haute',
                f"DKIM FAIL : la signature du mail ne correspond pas")
        elif dkim == 'NONE':
            self._ajouter_anomalie('faible',
                f"DKIM NONE : aucune signature DKIM presente")

        # DMARC
        if dmarc == 'FAIL':
            self._ajouter_anomalie('haute',
                f"DMARC FAIL : la politique du domaine rejette ce mail")
        elif dmarc == 'NONE':
            self._ajouter_anomalie('faible',
                f"DMARC NONE : aucune politique DMARC configuree")

    # ── Verification expediteur (existant, ameliore) ──
    def _verifier_expediteur(self, donnees: dict):
        expediteur = donnees.get('expediteur', '')
        reply_to = donnees.get('reply_to', '')

        # Domaine suspect
        match_domaine = re.search(r'@([\w\.-]+)', expediteur)
        if match_domaine:
            domaine = match_domaine.group(1).lower()
            # Trop de tirets
            if domaine.count('-') > 2:
                self._ajouter_anomalie('moyenne', f"Domaine suspect (tirets) : {domaine}")
            # Trop de chiffres
            if sum(c.isdigit() for c in domaine) > 3:
                self._ajouter_anomalie('moyenne', f"Domaine suspect (chiffres) : {domaine}")
            # Extensions exotiques
            tld = domaine.split('.')[-1] if '.' in domaine else ''
            tlds_suspects = ['xyz', 'top', 'buzz', 'click', 'loan', 'work', 'gq', 'tk', 'ml', 'cf']
            if tld in tlds_suspects:
                self._ajouter_anomalie('moyenne', f"TLD suspect : .{tld} ({domaine})")

        # Reply-To different du From
        if reply_to and reply_to.lower() != expediteur.lower():
            self._ajouter_anomalie('haute', f"Reply-To different du From : {reply_to}")

    # ── Detection URLs suspectes (existant) ──
    def _detecter_urls_suspectes(self, donnees: dict):
        corps = donnees.get('corps', '')
        corps_html = donnees.get('corps_html', '')
        urls_extraites = donnees.get('urls', [])
        
        # Extraire les URLs du corps texte
        urls_regex = re.findall(r'https?://[^\s<>"]+', f"{corps} {corps_html}", re.IGNORECASE)
        urls = list(set(urls_extraites + urls_regex))

        for url in urls:
            # URL raccourcie
            if re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|buff\.ly)', url, re.IGNORECASE):
                self._ajouter_anomalie('moyenne', f"URL raccourcie : {url[:80]}")
            # URL avec IP directe
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                self._ajouter_anomalie('haute', f"URL avec adresse IP : {url[:80]}")
            # HTTP sans S (non securise)
            if url.startswith('http://') and 'localhost' not in url:
                self._ajouter_anomalie('faible', f"URL non securisee (HTTP) : {url[:80]}")

    # ── Detection mots-cles phishing (existant, conserve) ──
    def _detecter_mots_cles_phishing(self, donnees: dict):
        sujet = donnees.get('sujet', '').lower()
        corps = donnees.get('corps', '').lower()
        corps_html = donnees.get('corps_html', '').lower()
        texte = f"{sujet} {corps} {corps_html}"

        mots_suspects = [
            # Urgence
            'urgent', 'action requise', 'immédiatement', 'dernier délai',
            'expire bientôt', 'dans les 24 heures', 'répondez vite',
            'ne tardez pas', 'temps limité', 'agissez maintenant',
            'sans délai', 'avant minuit', 'dernière chance',
            'plus que quelques heures', 'dépêchez-vous',
            # Compte compromis
            'compte bloqué', 'compte suspendu', 'accès refusé',
            'activité suspecte', 'connexion inhabituelle', 'accès limité',
            'votre compte sera fermé', 'sécurité compromise', 'compte désactivé',
            'tentative de connexion', 'accès non autorisé', 'compte piraté',
            'violation de sécurité', 'compte expiré', 'suspension imminente',
            # Donnees personnelles
            'mot de passe', 'identifiants', 'coordonnées bancaires',
            'numéro de carte', 'code secret', 'code pin',
            'informations personnelles', 'données confidentielles',
            'numéro de sécurité sociale', 'date de naissance',
            'adresse complète', 'pièce d identité', 'passeport',
            'rib bancaire', 'cvv', 'cryptogramme',
            # Appels a l'action
            'cliquez ici', 'cliquez maintenant', 'accédez ici',
            'vérifiez', 'confirmer', 'valider maintenant',
            'mettre à jour', 'réinitialisez', 'connectez-vous ici',
            'accéder à mon compte', 'suivez ce lien', 'ouvrir le document',
            'téléchargez maintenant', 'installer maintenant',
            # Gains / loterie
            'gagnant', 'vous avez gagné', 'félicitations',
            'cadeau gratuit', 'offre exclusive', 'sélectionné',
            'tirage au sort', 'loterie', 'récompense',
            'bonus exceptionnel', 'prix à récupérer', 'lot à retirer',
            'vous êtes l heureux gagnant', 'offre spéciale réservée',
            'iphone gratuit', 'bon cadeau', 'chèque cadeau',
            # Finance
            'virement urgent', 'transfert bancaire', 'remboursement en attente',
            'facture impayée', 'paiement refusé', 'régulariser',
            'dette en cours', 'huissier', 'mise en demeure',
            'recouvrement', 'saisie', 'pénalités',
            'trop perçu', 'avoir disponible', 'crédit offert',
            'investissement garanti', 'rendement exceptionnel',
            # Usurpation identite
            'service client', 'support technique', 'votre banque',
            'administration fiscale', 'impôts', 'amende',
            'police nationale', 'gendarmerie', 'interpol',
            'ministère', 'préfecture', 'sécurité sociale',
            'caisse d assurance', 'mutuelle', 'assurance maladie',
            'amazon', 'paypal', 'apple', 'microsoft', 'google',
            'la poste', 'chronopost', 'colissimo', 'dhl', 'fedex',
            # Pieces jointes
            'ouvrez la pièce jointe', 'voir le document joint',
            'facture en pièce jointe', 'votre colis', 'suivre ma livraison',
            'document important joint', 'fichier partagé',
            # Formules generiques
            'cher utilisateur', 'cher client', 'cher abonné',
            'nous avons remarqué', 'nous avons détecté',
            'votre participation', 'félicitation', 'vous bénéficiez',
            'profitez maintenant', 'ne manquez pas',
            # Anglais (courants)
            'verify your account', 'confirm your identity',
            'click here immediately', 'reset password',
            'unusual activity', 'account suspended',
            'dear customer', 'dear user',
        ]

        mots_trouves = []
        for mot in mots_suspects:
            if re.search(rf'\b{re.escape(mot)}\b', texte, re.IGNORECASE):
                mots_trouves.append(mot)

        if len(mots_trouves) >= 3:
            self._ajouter_anomalie('haute',
                f"Multiples mots-cles phishing ({len(mots_trouves)}) : {', '.join(mots_trouves[:5])}")
        elif len(mots_trouves) >= 2:
            self._ajouter_anomalie('moyenne',
                f"Mots-cles suspects ({len(mots_trouves)}) : {', '.join(mots_trouves)}")

    # ── NOUVEAU : Verification pieces jointes ──
    def _verifier_pieces_jointes(self, donnees: dict):
        pj = donnees.get('pieces_jointes', [])
        extensions_dangereuses = {'.exe', '.bat', '.scr', '.vbs', '.js', '.ps1', '.cmd', '.msi', '.hta'}
        doubles_extensions = re.compile(r'\.\w+\.\w+$')

        for fichier in pj:
            nom = fichier if isinstance(fichier, str) else fichier.get('filename', '')
            ext = nom.rsplit('.', 1)[-1].lower() if '.' in nom else ''

            if f'.{ext}' in extensions_dangereuses:
                self._ajouter_anomalie('haute', f"Piece jointe dangereuse : {nom}")
            if doubles_extensions.search(nom):
                self._ajouter_anomalie('haute', f"Double extension suspecte : {nom}")


def detecter_anomalies(donnees_email: dict) -> list:
    """Fonction wrapper pour compatibilite avec l'ancien code."""
    moteur = MoteurDetection()
    return moteur.analyser_email(donnees_email)
