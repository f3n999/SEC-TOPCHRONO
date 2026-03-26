# 🛡️ Phishing Detection Agent

**Analyse automatisée des emails via Microsoft Graph API — Détection heuristique en temps réel**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft_Graph-API-0078D4?logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/graph/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Table des matières

- [Présentation du projet](#-présentation-du-projet)
- [Contexte et problématique](#-contexte-et-problématique)
- [Architecture globale](#-architecture-globale)
- [Comment ça a commencé](#-comment-ça-a-commencé)
- [Étapes de développement](#-étapes-de-développement)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration Azure AD](#-configuration-azure-ad)
- [Utilisation](#-utilisation)
- [Moteur de détection](#-moteur-de-détection)
- [API Serveur](#-api-serveur)
- [Structure du projet](#-structure-du-projet)
- [Équipe](#-équipe)
- [Axes d'amélioration](#-axes-damélioration)
- [Ressources et documentation](#-ressources-et-documentation)

---

## 🎯 Présentation du projet

Le **Phishing Detection Agent** est un outil de cybersécurité conçu pour scanner automatiquement les boîtes mail d'un tenant Microsoft 365, détecter les tentatives de phishing à l'aide d'un moteur heuristique, et produire des rapports chiffrés exploitables.

**L'agent observe et mesure. Il ne bloque rien.** Son objectif est de fournir des données factuelles pour justifier le déploiement d'une solution de protection avancée (Microsoft Defender for Office 365 / Threat Explorer) auprès de la DSI.

### Ce que fait l'agent

- **Scanne** toutes les boîtes mail du tenant via l'API Microsoft Graph
- **Analyse** les headers techniques (SPF, DKIM, DMARC, Reply-To)
- **Détecte** les mots-clés de phishing (100+ termes FR/EN)
- **Score** chaque email de 0 à 100 (LOW / MEDIUM / HIGH)
- **Stocke** les résultats dans une base SQLite sur un serveur Linux
- **Exporte** en CSV (Excel), JSON, et via une API REST en temps réel

### Ce que l'agent ne fait PAS

- Il ne bloque aucun email
- Il ne supprime rien
- Il ne modifie aucune boîte mail
- Il n'accède pas au contenu des emails (corps, pièces jointes) — uniquement les métadonnées

---

## 🔍 Contexte et problématique

### Le constat

Le phishing représente **91% des cyberattaques** en entreprise (source : Verizon DBIR). Le coût moyen d'un incident de phishing réussi est estimé à **45 000€** (source : IBM Cost of a Data Breach).

Dans un environnement Microsoft 365, les emails transitent par Exchange Online sans qu'aucune visibilité fine ne soit offerte nativement sur le volume et la nature des tentatives de phishing reçues.

### Le besoin

L'organisation ne dispose d'aucun outil de mesure dédié. **Sans données, impossible de justifier un investissement** en protection email auprès de la direction.

### La stratégie

1. **Mesurer** — Déployer un agent de scan pour quantifier les tentatives de phishing
2. **Prouver** — Produire un rapport chiffré avec tendances et statistiques
3. **Recommander** — Justifier le déploiement de Threat Explorer avec des données réelles

---

## 🏗️ Architecture globale

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│   AGENT WINDOWS         │         │   SERVEUR LINUX              │
│                         │         │                              │
│  ┌───────────────────┐  │  HTTP   │  ┌────────────────────────┐  │
│  │ Microsoft Graph   │  │  POST   │  │ FastAPI (port 8000)    │  │
│  │ API (OAuth2)      │  │ ──────> │  │                        │  │
│  └────────┬──────────┘  │         │  │  POST /api/scan        │  │
│           │              │         │  │  GET  /api/stats       │  │
│  ┌────────▼──────────┐  │         │  │  GET  /api/scans       │  │
│  │ Moteur Heuristique│  │         │  │  GET  /api/detections  │  │
│  │ SPF/DKIM/DMARC    │  │         │  └────────┬───────────────┘  │
│  │ Keywords + URLs   │  │         │           │                  │
│  └────────┬──────────┘  │         │  ┌────────▼───────────────┐  │
│           │              │         │  │ SQLite Database        │  │
│  ┌────────▼──────────┐  │         │  │ phishing_agent.db      │  │
│  │ Scoring 0-100     │  │         │  │                        │  │
│  │ LOW/MEDIUM/HIGH   │  │         │  │ Tables:                │  │
│  └────────┬──────────┘  │         │  │  - scans               │  │
│           │              │         │  │  - detections          │  │
│  ┌────────▼──────────┐  │         │  └────────────────────────┘  │
│  │ Export CSV + JSON  │  │         │                              │
│  └───────────────────┘  │         │  Documentation interactive:  │
│                         │         │  http://IP:8000/docs         │
└─────────────────────────┘         └──────────────────────────────┘
```

### Flux d'authentification OAuth2

```
┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Azure AD    │     │  Token Endpoint      │     │  Graph API       │
│  App         │────>│  login.microsoft     │────>│  graph.microsoft │
│  Registration│     │  online.com          │     │  .com/v1.0       │
│              │     │                      │     │                  │
│  tenant_id   │     │  POST /oauth2/token  │     │  GET /users      │
│  client_id   │     │  → access_token JWT  │     │  GET /messages   │
│  client_secret│    │  (valide 1 heure)    │     │  + headers auth  │
└──────────────┘     └─────────────────────┘     └──────────────────┘
```

---

## 📖 Comment ça a commencé

### Phase 0 — L'existant (base de code initiale)

Le projet est parti d'un **analyseur de fichiers .eml en ligne de commande**. Un ensemble de scripts Python capables de :

- Parser un fichier `.eml` local (`email_parser.py`)
- Détecter les anomalies via des règles heuristiques (`detection_rules.py`)
- Calculer un score de risque 0-100 (`risk_scorer.py`)
- Exporter un rapport texte (`exporters.py`)

Ces scripts fonctionnaient sur des fichiers individuels, en local, sans connexion à aucun système de messagerie.

**Fichiers de test initiaux :**
- `legitime.eml` — Newsletter Spotify authentique → Score 0/100, ALLOW
- `phishing.eml` — Faux email bancaire avec Reply-To hacker, URL avec IP, mots-clés de phishing → Score 100/100, BLOCK

### Phase 1 — La demande

Le responsable a demandé : *"Est-ce qu'on peut mettre en place un agent pour analyser combien de mails de phishing on reçoit ?"*

L'objectif : **prouver le besoin** d'une solution Threat Explorer auprès de la DSI, avec des données réelles.

### Phase 2 — Conception de l'architecture

Avant d'écrire une seule ligne de code, on a conçu l'architecture complète :

1. **Choix technologique** — Microsoft Graph API pour accéder aux boîtes mail M365
2. **Méthode d'authentification** — OAuth2 Client Credentials (app-only, sans utilisateur connecté)
3. **Données collectées** — Headers uniquement (pas de corps d'email → conformité RGPD)
4. **Moteur de détection** — Adaptation du moteur existant + ajout SPF/DKIM/DMARC
5. **Stockage** — SQLite sur serveur Linux avec API REST (FastAPI)

### Phase 3 — Développement brique par brique

On a construit le projet **de manière incrémentale**, en testant chaque composant avant de passer au suivant :

1. **Brique 1 — Authentification** : obtention du token OAuth2 ✅
2. **Brique 2 — Collecte** : listing des users + récupération des mails ✅
3. **Brique 3 — Analyse** : intégration du moteur heuristique avec les données Graph ✅
4. **Brique 4 — Export** : CSV + JSON + envoi au serveur ✅
5. **Brique 5 — Infrastructure** : serveur Linux + API FastAPI + base SQLite ✅
6. **Brique 6 — Automatisation** : scan automatique via Task Scheduler ✅

---

## 🔧 Étapes de développement

### Étape 1 : Enregistrement de l'application Azure AD

On a créé une **App Registration** dans Microsoft Entra ID (anciennement Azure AD) pour permettre à l'agent de s'authentifier auprès de l'API Graph.

- **Portail** : portal.azure.com → Entra ID → Inscriptions d'applications
- **Nom de l'app** : `PhishingDetectionAgent`
- **Type** : Single tenant (comptes de cette organisation uniquement)
- **Permissions** : `Mail.Read` + `User.Read.All` (Application, pas Delegated)
- **Admin consent** : accordé par l'administrateur

> **Piège rencontré** : ne pas confondre le "Secret ID" avec la "Value" du secret. Le Secret ID est inutile — c'est la **Value** qu'il faut copier, et elle n'est affichée **qu'une seule fois**.

### Étape 2 : Premier test d'authentification

On a validé que le token OAuth2 était correctement obtenu et que l'API Graph répondait. Le script `agent.py` en option 1 affiche le token, et l'option 2 liste les utilisateurs du tenant.

> **Erreur rencontrée** : `403 Authorization_RequestDenied` — il manquait la permission `User.Read.All` en mode Application. Solution : ajouter la permission et accorder le consentement admin.

### Étape 3 : Accès aux boîtes mail

On a étendu `graph.py` pour récupérer les messages d'un utilisateur, incluant les `internetMessageHeaders` qui contiennent les résultats SPF/DKIM/DMARC.

> **Erreur rencontrée** : `401 Unauthorized` sur les mails — le tenant Azure for Students n'incluait pas de licence Exchange Online. Solution : migration vers un essai gratuit Microsoft 365 Business Basic (30 jours).

> **Piège rencontré** : les comptes externes (#EXT#) n'ont pas de boîte mail dans le tenant. Il faut scanner uniquement les utilisateurs natifs du tenant (UPN en `@domaine.onmicrosoft.com`).

### Étape 4 : Intégration du moteur de détection

On a adapté le `MoteurDetection` existant pour fonctionner avec les données provenant de Graph API au lieu de fichiers `.eml` :

- **Ajout** : vérification SPF/DKIM/DMARC depuis les headers `Authentication-Results`
- **Ajout** : détection des TLD exotiques (.xyz, .top, .buzz...)
- **Ajout** : vérification des doubles extensions sur les pièces jointes
- **Conservation** : toutes les règles existantes (Reply-To, URLs, mots-clés)
- **Ajout** : mots-clés en anglais (verify, confirm, suspended...)

### Étape 5 : Export et reporting

Le module `exporters.py` a été entièrement réécrit :

- **Console** : affichage résumé avec stats (total, phishing, suspects, taux de détection)
- **CSV** : compatible Excel (séparateur `;`, encodage UTF-8 BOM)
- **JSON** : structure complète avec summary + détails pour traitement automatisé
- **Serveur** : envoi HTTP POST au serveur Linux en temps réel

### Étape 6 : Déploiement du serveur Linux

On a déployé un serveur **FastAPI** sur une machine Linux interne (192.168.237.133) :

- **Base de données** : SQLite avec deux tables (scans + detections)
- **API REST** : endpoints pour recevoir, consulter et analyser les résultats
- **Service systemd** : le serveur tourne en permanence et redémarre automatiquement
- **Documentation** : Swagger UI accessible sur `http://IP:8000/docs`

### Étape 7 : Automatisation

Un script `auto_scan.py` non-interactif permet l'exécution automatique via le **Planificateur de tâches Windows**. Le scan tourne tous les jours, scanne toutes les boîtes, et envoie les résultats au serveur.

---

## 📦 Prérequis

### Agent Windows

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.10+ | [python.org](https://python.org) |
| azure-identity | dernière | `pip install azure-identity` |
| msgraph-sdk | dernière | `pip install msgraph-sdk` |
| requests | dernière | `pip install requests` |

### Serveur Linux

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.10+ | `sudo apt install python3 python3-pip python3-venv` |
| FastAPI | 0.115+ | `pip install fastapi` |
| Uvicorn | 0.30+ | `pip install uvicorn` |

### Azure / Microsoft 365

| Composant | Détail |
|-----------|--------|
| Tenant Microsoft 365 | Business Basic minimum (avec Exchange Online) |
| Rôle | Administrateur Global (pour créer l'App Registration) |
| Permissions Graph API | `Mail.Read` + `User.Read.All` (Application) |

---

## 🚀 Installation

### 1. Cloner le repo

```bash
git clone https://github.com/votre-repo/phishing-detection-agent.git
cd phishing-detection-agent
```

### 2. Installer les dépendances de l'agent

```bash
pip install azure-identity msgraph-sdk requests
```

### 3. Configurer les credentials Azure

Créer un fichier `config.cfg` à la racine du projet :

```ini
[azure]
clientId = VOTRE_CLIENT_ID
clientSecret = VOTRE_CLIENT_SECRET
tenantId = VOTRE_TENANT_ID
```

> ⚠️ **Ne jamais commit ce fichier.** Il est dans le `.gitignore`.

### 4. Déployer le serveur Linux

```bash
# Copier les fichiers sur la machine Linux
scp server/server.py server/deploy.sh server/requirements.txt user@192.168.237.133:/tmp/

# Se connecter en SSH
ssh user@192.168.237.133

# Lancer le déploiement
chmod +x /tmp/deploy.sh
sudo bash /tmp/deploy.sh
```

### 5. Vérifier le serveur

```bash
curl http://192.168.237.133:8000/api/health
# Réponse attendue : {"status":"ok","db":"connected"}
```

---

## ⚙️ Configuration Azure AD

### Pas à pas

1. Aller sur **[portal.azure.com](https://portal.azure.com)**
2. Chercher **"Inscriptions d'applications"** (ou "App registrations")
3. Cliquer **"+ Nouvelle inscription"**
   - Nom : `PhishingDetectionAgent`
   - Type : Comptes dans cet annuaire uniquement
   - URI de redirection : vide
4. **Page Overview** — copier :
   - `ID d'application (client)` → c'est le `clientId`
   - `ID de l'annuaire (locataire)` → c'est le `tenantId`
5. **Certificats & secrets → + Nouveau secret client**
   - Copier la colonne **"Valeur"** immédiatement (pas le "ID du secret")
   - ⚠️ Elle n'est affichée qu'une seule fois
6. **API autorisées → + Ajouter une autorisation**
   - Microsoft Graph → Autorisations d'application
   - Cocher `Mail.Read` et `User.Read.All`
   - Cliquer **"Accorder un consentement d'administrateur"**
   - Vérifier que les deux permissions sont en vert ✅

### Documentation officielle

| Ressource | Lien |
|-----------|------|
| Tutoriel Python app-only | [learn.microsoft.com/graph/tutorials/python-app-only](https://learn.microsoft.com/en-us/graph/tutorials/python-app-only?tabs=aad) |
| Flux Client Credentials | [learn.microsoft.com/graph/auth-v2-service](https://learn.microsoft.com/en-us/graph/auth-v2-service?tabs=http) |
| Trouver le Tenant ID | [learn.microsoft.com/entra/fundamentals/how-to-find-tenant](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant) |

---

## 💻 Utilisation

### Mode interactif (développement / démo)

```bash
cd files
python agent.py
```

```
==================================================
  PHISHING DETECTION AGENT v2.0
  Microsoft Graph API + Moteur Heuristique
==================================================

[OK] Client Graph initialise.

+----------------------------------------------+
|  MENU PRINCIPAL                              |
+----------------------------------------------+
|  1. Verifier le token                        |
|  2. Lister les utilisateurs                  |
|  3. Scan rapide (10 mails, 1 user)           |
|  4. Scan complet + Rapport (CSV/JSON)        |
|  0. Quitter                                  |
+----------------------------------------------+
```

| Option | Description |
|--------|-------------|
| **1** | Vérifie que l'authentification OAuth2 fonctionne |
| **2** | Liste tous les utilisateurs du tenant avec leur UPN et mail |
| **3** | Scan rapide : analyse les 10 derniers mails d'un utilisateur avec détection inline |
| **4** | Scan complet : scanne toutes les boîtes, génère CSV + JSON, envoie au serveur |

### Mode automatique (production)

```bash
cd files
python auto_scan.py
```

Ce script scanne automatiquement **tous les utilisateurs** sans intervention. Il est conçu pour être lancé via le **Planificateur de tâches Windows** :

1. Ouvrir **Planificateur de tâches** (Task Scheduler)
2. Créer une tâche de base → Nom : `Phishing Detection Scan`
3. Déclencheur : tous les jours à 08h00
4. Action : démarrer `run_scan.bat`

### Exemple de sortie (scan rapide)

```
[SCAN] Analyse des 10 derniers mails de Admin...

======================================================================
  [ OK] LEGITIME | Score: 0/100
  Date  : 2026-03-23 11:26
  De    : mohamed.elnaggar@oteria.fr
  Sujet : Test interne
  SPF: PASS | DKIM: PASS | DMARC: PASS
----------------------------------------------------------------------
  [!!!] PHISHING | Score: 100/100
  Date  : 2026-03-23 11:30
  De    : security@ma-banque-secure-123.com
  Sujet : URGENT - Votre compte sera ferme dans 24h
  SPF: FAIL | DKIM: FAIL | DMARC: FAIL
    -> [haute] SPF FAIL : le serveur expediteur n'est pas autorise
    -> [haute] DKIM FAIL : la signature du mail ne correspond pas
    -> [haute] DMARC FAIL : la politique du domaine rejette ce mail
    -> [haute] Reply-To different du From : hacker@gmail.com
    -> [haute] URL avec adresse IP : http://192.168.1.42/login
    -> [haute] Multiples mots-cles phishing (12) : urgent, activité suspecte...
----------------------------------------------------------------------
```

---

## 🔬 Moteur de détection

### Règles heuristiques

Le moteur de détection (`detection_rules.py`) applique **5 catégories de vérification** sur chaque email :

| # | Catégorie | Vérification | Sévérité | Points |
|---|-----------|-------------|----------|--------|
| 1 | Auth Headers | SPF FAIL | Haute | +40 |
| 2 | Auth Headers | SPF SOFTFAIL | Moyenne | +20 |
| 3 | Auth Headers | DKIM FAIL | Haute | +40 |
| 4 | Auth Headers | DMARC FAIL | Haute | +40 |
| 5 | Expéditeur | Reply-To ≠ From | Haute | +40 |
| 6 | Expéditeur | Domaine suspect (tirets/chiffres) | Moyenne | +20 |
| 7 | Expéditeur | TLD exotique (.xyz, .top...) | Moyenne | +20 |
| 8 | URLs | URL avec adresse IP | Haute | +40 |
| 9 | URLs | URL raccourcie (bit.ly...) | Moyenne | +20 |
| 10 | URLs | HTTP non sécurisé | Faible | +5 |
| 11 | Mots-clés | 2 mots-clés phishing | Moyenne | +20 |
| 12 | Mots-clés | 3+ mots-clés phishing | Haute | +40 |
| 13 | Pièces jointes | Extension dangereuse (.exe...) | Haute | +40 |
| 14 | Pièces jointes | Double extension | Haute | +40 |

### Système de scoring

| Plage | Niveau | Action | Interprétation |
|-------|--------|--------|----------------|
| 0-30 | **LOW** | ALLOW | Email probablement légitime |
| 31-60 | **MEDIUM** | REVIEW | Suspect — vérification humaine recommandée |
| 61-100 | **HIGH** | BLOCK | Phishing probable — multiples indicateurs |

### Mots-clés détectés (100+ termes)

**Urgence** : urgent, action requise, dernier délai, avant minuit, dépêchez-vous...

**Compte compromis** : compte bloqué, activité suspecte, suspension imminente, accès non autorisé...

**Données personnelles** : mot de passe, coordonnées bancaires, code pin, numéro de carte...

**Appels à l'action** : cliquez ici, vérifiez, connectez-vous ici, téléchargez maintenant...

**Gains / loterie** : vous avez gagné, cadeau gratuit, offre exclusive, loterie...

**Finance** : virement urgent, facture impayée, mise en demeure, huissier...

**Usurpation d'identité** : service client, votre banque, police nationale, amazon, paypal...

**Anglais** : verify your account, confirm your identity, unusual activity, dear customer...

---

## 🌐 API Serveur

Le serveur Linux expose une **API REST** documentée via Swagger UI.

**Documentation interactive** : `http://192.168.237.133:8000/docs`

### Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/api/health` | Vérifie que le serveur et la DB fonctionnent |
| `POST` | `/api/scan` | Reçoit un batch de résultats de scan |
| `GET` | `/api/scans` | Liste les derniers scans (avec pagination) |
| `GET` | `/api/scans/{id}` | Détails d'un scan avec toutes les détections |
| `GET` | `/api/stats` | Statistiques globales (totaux, tendances, top domaines) |
| `GET` | `/api/detections` | Liste les détections, filtrable par niveau |

### Exemples

```bash
# Stats globales
curl http://192.168.237.133:8000/api/stats

# Emails phishing uniquement
curl "http://192.168.237.133:8000/api/detections?niveau=HIGH"

# Détails du scan #1
curl http://192.168.237.133:8000/api/scans/1

# Accès direct à la base SQLite (sur le serveur)
sqlite3 /opt/phishing-server/phishing_agent.db "SELECT * FROM detections WHERE niveau='HIGH';"
```

### Schéma de la base de données

```sql
-- Table des scans (1 ligne par exécution de l'agent)
CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT NOT NULL,
    scan_date       TEXT NOT NULL,
    total_emails    INTEGER DEFAULT 0,
    phishing_count  INTEGER DEFAULT 0,
    suspect_count   INTEGER DEFAULT 0,
    legitime_count  INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Table des détections (1 ligne par email analysé)
CREATE TABLE detections (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL,
    boite             TEXT,
    date_reception    TEXT,
    expediteur        TEXT,
    sujet             TEXT,
    spf               TEXT DEFAULT '?',
    dkim              TEXT DEFAULT '?',
    dmarc             TEXT DEFAULT '?',
    reply_to_mismatch INTEGER DEFAULT 0,
    score             INTEGER DEFAULT 0,
    niveau            TEXT DEFAULT 'LOW',
    action            TEXT DEFAULT '',
    anomalies         TEXT DEFAULT '[]',
    created_at        TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

---

## 📁 Structure du projet

```
phishing-detection-agent/
│
├── config.cfg                      # Credentials Azure (NE PAS COMMIT)
├── .gitignore                      # Fichiers exclus du repo
├── README.md                       # Ce fichier
│
├── files/                          # Code de l'agent (Windows)
│   ├── agent.py                    # Menu interactif (dev/démo)
│   ├── auto_scan.py                # Scan automatique (production)
│   ├── graph.py                    # Client Microsoft Graph API
│   ├── detection_rules.py          # Moteur de détection heuristique
│   ├── risk_scorer.py              # Scoring 0-100 + niveaux
│   ├── exporters.py                # Export CSV + JSON + envoi serveur
│   └── run_scan.bat                # Lanceur pour Task Scheduler
│
├── server/                         # Code du serveur (Linux)
│   ├── server.py                   # API FastAPI + SQLite
│   ├── deploy.sh                   # Script d'installation automatique
│   └── requirements.txt            # Dépendances Python serveur
│
├── docs/                           # Documentation
│   ├── conception-agent.docx       # Document de conception technique
│   ├── brique1_authentification.pdf# Guide OAuth2 détaillé
│   └── presentation_phishing_agent.pptx # Présentation (12 slides)
│
├── tests/                          # Fichiers de test
│   ├── legitime.eml                # Email légitime (score 0)
│   └── phishing.eml                # Email phishing (score 100)
│
├── lien_important.txt              # Liens documentation Microsoft
├── Python_avec_Microsoft.txt       # Notes tutoriel Graph API
└── figma.txt                       # Lien vers le diagramme d'architecture
```

---

## 👥 Équipe

Ce projet est développé par une équipe de 4 personnes dans le cadre d'un projet de sécurité informatique.

| Membre | Rôle |
|--------|------|
| **Mohamed Elnaggar** | Backend API, déploiement serveur, moteur de détection |
| **Membre 2** | À compléter |
| **Membre 3** | À compléter |
| **Membre 4** | À compléter |

---

## 🚀 Axes d'amélioration

### Court terme (v1.5)

- [ ] Dashboard web interactif pour visualiser les stats
- [ ] Alertes email automatiques quand un phishing est détecté
- [ ] Scan du corps des emails (avec opt-in conformité)
- [ ] Enrichissement des domaines via WHOIS (date de création, registrar)
- [ ] Analyse des pièces jointes (hash, type MIME)

### Moyen terme (v2.0)

- [ ] Déploiement de Microsoft Defender for Office 365 (Threat Explorer)
- [ ] Corrélation des données de l'agent avec Defender
- [ ] Machine Learning sur les patterns de phishing détectés
- [ ] Intégration SIEM (Microsoft Sentinel)
- [ ] API d'enrichissement via MISP (Threat Intelligence)

### Long terme (v3.0)

- [] Campagnes de simulation de phishing internes
- [ ] Module de formation et sensibilisation des utilisateurs
- [ ] Reporting mensuel automatisé pour la DSI
- [ ] Score de maturité sécurité de l'organisation
- [ ] Extension à d'autres vecteurs (Teams, SharePoint)

---

## 📚 Ressources et documentation

### Documentation officielle Microsoft

| Ressource | URL |
|-----------|-----|
| Tutoriel Python Graph API (app-only) | https://learn.microsoft.com/en-us/graph/tutorials/python-app-only |
| Flux OAuth2 Client Credentials | https://learn.microsoft.com/en-us/graph/auth-v2-service |
| Trouver le Tenant ID | https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant |
| API Messages Graph | https://learn.microsoft.com/en-us/graph/api/user-list-messages |
| Concepts Auth Graph | https://learn.microsoft.com/en-us/graph/auth/auth-concepts |

### Références cybersécurité

| Source | Utilisation |
|--------|------------|
| Verizon DBIR | Statistiques sur les vecteurs d'attaque (91% phishing) |
| IBM Cost of a Data Breach | Coût moyen des incidents |
| ANSSI | Recommandations sécurité email |

### Livrables du projet

| Document | Description |
|----------|-------------|
| `conception-agent.docx` | Document de conception technique complet |
| `brique1_authentification.pdf` | Guide détaillé de l'authentification OAuth2 |
| `presentation_phishing_agent.pptx` | Présentation 12 slides pour collègues/DSI |
| Diagramme FigJam | [Architecture détaillée](https://www.figma.com/board/MqXzudGzotR02BlzsEMtQY/Phishing-Detection-Agent---Architecture-Detaillee-Complete) |

---

## ⚠️ Avertissements

- **Conformité RGPD** : L'agent ne collecte que les métadonnées techniques (expéditeur, sujet, headers). Le corps des emails et les pièces jointes ne sont pas lus. Validation DPO requise avant déploiement production.
- **Credentials** : Ne jamais commit le fichier `config.cfg`. Utiliser des variables d'environnement en production.
- **Scope** : L'agent est un outil de **mesure**, pas de **protection**. Il ne bloque, ne supprime, et ne modifie aucun email.
- **Permissions** : `Mail.Read` en mode Application donne accès en lecture à **toutes les boîtes mail** du tenant. Admin consent requis.

---

## 📄 Licence

MIT License — voir [LICENSE](LICENSE) pour les détails.

---

*Phishing Detection Agent — Premier projet sécurité. Première brique d'une longue série.* 🛡️
