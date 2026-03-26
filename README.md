# Phishing Detection Agent - SEC-TOPCHRONO

**Analyse automatisee des emails via Microsoft Graph API -- Detection heuristique en temps reel**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft_Graph-API-0078D4?logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/graph/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Table des matieres

- [Presentation du projet](#presentation-du-projet)
- [Contexte et problematique](#contexte-et-problematique)
- [Architecture globale](#architecture-globale)
- [Evolution du projet (V1 - V2 - V3)](#evolution-du-projet-v1---v2---v3)
- [Ce qui a ete augmente (V2 vers V3)](#ce-qui-a-ete-augmente-v2-vers-v3)
- [Etapes de developpement](#etapes-de-developpement)
- [Prerequis](#prerequis)
- [Installation et execution](#installation-et-execution)
- [Configuration Azure AD](#configuration-azure-ad)
- [Utilisation - Toutes les commandes](#utilisation---toutes-les-commandes)
- [Rendre le systeme persistant](#rendre-le-systeme-persistant)
- [Moteur de detection](#moteur-de-detection)
- [API Serveur (endpoints)](#api-serveur-endpoints)
- [Schema de la base de donnees](#schema-de-la-base-de-donnees)
- [Structure du projet](#structure-du-projet)
- [References et documentation](#references-et-documentation)
- [Equipe](#equipe)
- [Axes d'amelioration](#axes-damelioration)
- [Avertissements](#avertissements)

---

## Presentation du projet

Le **Phishing Detection Agent** est un outil de cybersecurite concu pour scanner automatiquement les boites mail d'un tenant Microsoft 365, detecter les tentatives de phishing a l'aide d'un moteur heuristique, et produire des rapports chiffres exploitables.

**L'agent observe et mesure. Il ne bloque rien.** Son objectif est de fournir des donnees factuelles pour justifier le deploiement d'une solution de protection avancee (Microsoft Defender for Office 365 / Threat Explorer) aupres de la DSI.

### Ce que fait l'agent

- **Scanne** toutes les boites mail du tenant via l'API Microsoft Graph
- **Analyse** les headers techniques (SPF, DKIM, DMARC, Reply-To)
- **Detecte** les mots-cles de phishing (100+ termes FR/EN)
- **Detecte** les homoglyphes (substitutions de caracteres : 0->o, 1->l, etc.)
- **Score** chaque email de 0 a 100 (LOW / MEDIUM / HIGH)
- **Stocke** les resultats dans une base SQLite sur un serveur Linux
- **Exporte** en CSV (Excel), JSON, et via une API REST en temps reel
- **Planifie** des scans automatiques recurrents (Task Scheduler + APScheduler)

### Ce que l'agent ne fait PAS

- Il ne bloque aucun email
- Il ne supprime rien
- Il ne modifie aucune boite mail
- Il n'accede pas au contenu des emails (corps, pieces jointes) -- uniquement les metadonnees

---

## Contexte et problematique

### Le constat

Le phishing represente **91% des cyberattaques** en entreprise (source : Verizon DBIR). Le cout moyen d'un incident de phishing reussi est estime a **45 000 euros** (source : IBM Cost of a Data Breach).

Dans un environnement Microsoft 365, les emails transitent par Exchange Online sans qu'aucune visibilite fine ne soit offerte nativement sur le volume et la nature des tentatives de phishing recues.

### Le besoin

L'organisation ne dispose d'aucun outil de mesure dedie. **Sans donnees, impossible de justifier un investissement** en protection email aupres de la direction.

### La strategie

1. **Mesurer** -- Deployer un agent de scan pour quantifier les tentatives de phishing
2. **Prouver** -- Produire un rapport chiffre avec tendances et statistiques
3. **Recommander** -- Justifier le deploiement de Threat Explorer avec des donnees reelles

---

## Architecture globale

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   AGENT WINDOWS             │         │   SERVEUR LINUX              │
│                             │         │   192.168.237.133             │
│  ┌───────────────────────┐  │         │                              │
│  │ Microsoft Graph API   │  │         │  ┌────────────────────────┐  │
│  │ OAuth2 Client Creds   │  │  HTTP   │  │ FastAPI (port 8000)    │  │
│  │ - GET /users          │  │  POST   │  │                        │  │
│  │ - GET /messages       │  │ ──────> │  │  POST /api/scan        │  │
│  │ + internetMsgHeaders  │  │         │  │  GET  /api/stats       │  │
│  └────────┬──────────────┘  │         │  │  GET  /api/scans       │  │
│           │                 │         │  │  GET  /api/scans/{id}  │  │
│  ┌────────▼──────────────┐  │         │  │  GET  /api/detections  │  │
│  │ Moteur Heuristique    │  │         │  │  GET  /api/health      │  │
│  │ 6 modules detection   │  │         │  └────────┬───────────────┘  │
│  │ SPF/DKIM/DMARC        │  │         │           │                  │
│  │ Keywords + URLs       │  │         │  ┌────────▼───────────────┐  │
│  │ Homoglyphes           │  │         │  │ SQLite Database        │  │
│  │ Pieces jointes        │  │         │  │ phishing_agent.db      │  │
│  └────────┬──────────────┘  │         │  │                        │  │
│           │                 │         │  │ Tables:                │  │
│  ┌────────▼──────────────┐  │         │  │  - scans               │  │
│  │ Scoring 0-100         │  │         │  │  - detections          │  │
│  │ LOW / MEDIUM / HIGH   │  │         │  └────────────────────────┘  │
│  └────────┬──────────────┘  │         │                              │
│           │                 │         │  Swagger UI:                 │
│  ┌────────▼──────────────┐  │         │  http://IP:8000/docs         │
│  │ Export                │  │         └──────────────────────────────┘
│  │ CSV + JSON + Console  │  │
│  │ + envoi API REST      │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

### Flux d'authentification OAuth2

```
┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Azure AD    │     │  Token Endpoint      │     │  Graph API       │
│  App         │────>│  login.microsoft     │────>│  graph.microsoft │
│  Registration│     │  online.com          │     │  .com/v1.0       │
│              │     │                      │     │                  │
│  tenant_id   │     │  POST /oauth2/token  │     │  GET /users      │
│  client_id   │     │  -> access_token JWT │     │  GET /messages   │
│  client_secret│    │  (valide 1 heure)    │     │  + headers auth  │
└──────────────┘     └─────────────────────┘     └──────────────────┘
```

### Architecture V3 detaillee

```
                    ┌─────────────────────────────────────────────┐
                    │              PHISHING AGENT V3               │
                    └─────────────────────────────────────────────┘

    ┌──────────┐    ┌──────────┐    ┌─────────────────────────────┐
    │  CLI     │    │ FastAPI  │    │  Scheduler (APScheduler)    │
    │  (Typer) │    │  REST    │    │  - Cron scans               │
    │          │    │  API     │    │  - Scan differentiel        │
    └────┬─────┘    └────┬─────┘    └────────────┬────────────────┘
         │               │                       │
         └───────────────┼───────────────────────┘
                         │
              ┌──────────▼──────────┐
              │    SCANNER CORE     │
              │  (Orchestrateur)    │
              ├─────────────────────┤
              │ - Charge les users  │
              │ - Recupere emails   │
              │ - Lance detection   │
              │ - Calcule scores    │
              │ - Persiste resultats│
              └──────────┬──────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
  │ GRAPH       │ │ DETECTION   │ │ SCORING     │
  │ CLIENT      │ │ ENGINE      │ │ ENGINE      │
  ├─────────────┤ ├─────────────┤ ├─────────────┤
  │ MS Graph API│ │ 6 modules   │ │ Heuristique │
  │ Async       │ │ regles YAML │ │  (60%)      │
  │ Pagination  │ │ dynamiques  │ │ ML (30%)    │
  │ Differentiel│ │             │ │ Threat (10%)│
  └─────────────┘ └──────┬──────┘ └─────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
  │ AUTH        │ │ CONTENT     │ │ THREAT      │
  │ HEADERS     │ │ ANALYSIS    │ │ INTEL       │
  ├─────────────┤ ├─────────────┤ ├─────────────┤
  │ SPF/DKIM/   │ │ URLs        │ │ VirusTotal  │
  │ DMARC       │ │ Keywords    │ │ AbuseIPDB   │
  │             │ │ Attachments │ │ PhishTank   │
  │             │ │ Homoglyphes │ │ HIBP        │
  └─────────────┘ └─────────────┘ └─────────────┘
                         │
              ┌──────────▼──────────┐
              │    PERSISTENCE      │
              │  SQLAlchemy ORM     │
              ├─────────────────────┤
              │ 5 modeles :         │
              │ - ScanSession       │
              │ - ScanResultRow     │
              │ - WhitelistEntry    │
              │ - ThreatIndicator   │
              │ - BaselineData      │
              └──────────┬──────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
  │ EXPORT      │ │ ALERTING    │ │ API         │
  ├─────────────┤ ├─────────────┤ ├─────────────┤
  │ JSON / CSV  │ │ Webhook     │ │ Stats       │
  │ Console     │ │ Email       │ │ Tendances   │
  │ REST API    │ │ Slack/Teams │ │ Top menaces │
  └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Evolution du projet (V1 - V2 - V3)

### Phase 0 -- L'existant (base de code initiale)

Le projet est parti d'un **analyseur de fichiers .eml en ligne de commande**. Des scripts Python capables de parser un fichier `.eml` local, detecter les anomalies via des regles heuristiques, calculer un score de risque 0-100 et exporter un rapport texte.

Ces scripts fonctionnaient sur des fichiers individuels, en local, sans connexion a aucun systeme de messagerie.

### Phase 1 -- La demande

Le responsable a demande : *"Est-ce qu'on peut mettre en place un agent pour analyser combien de mails de phishing on recoit ?"*

L'objectif : **prouver le besoin** d'une solution Threat Explorer aupres de la DSI, avec des donnees reelles.

### Tableau d'evolution

| Version | Ce qui a ete fait | Emplacement |
|---------|-------------------|-------------|
| **V1** | Script de base : auth OAuth2 + lecture d'emails via Graph API | `agent.py` + `graph.py` (racine) |
| **V2** | Agent complet : menu interactif, moteur heuristique 14 regles, scoring 0-100, export CSV/JSON/API, serveur Linux FastAPI + SQLite, automatisation Task Scheduler | `files/` + `SRV/` |
| **V3** | Refactoring complet : async, CLI Typer, regles YAML configurables, SQLAlchemy ORM (5 modeles), Docker, tests pytest, APScheduler, detection homoglyphes, scoring pondere | `V3/v3/` |

---

## Ce qui a ete augmente (V2 vers V3)

| Aspect | V2 (avant) | V3 (apres) |
|--------|------------|------------|
| **Moteur de detection** | 1 fichier monolithique (`detection_rules.py`) | 6 modules separes + fichier `rules.yaml` configurable |
| **Homoglyphes** | Non existant | Nouveau module (`homoglyphs.py`) -- detecte les substitutions 0->o, 1->l, etc. |
| **Base de donnees** | Simple POST HTTP vers serveur | SQLAlchemy ORM async avec 5 modeles (ScanSession, ScanResultRow, WhitelistEntry, ThreatIndicator, BaselineData) |
| **CLI** | `input()` basique avec menu numerote | Typer avec auto-completion + Rich pour le formatage console |
| **Scheduling** | Task Scheduler Windows uniquement | APScheduler integre (cron Python) + scans differentiels |
| **API serveur** | Routes dans un seul fichier | Architecture routes separees (health, scan, reports) |
| **Deploiement** | Copie manuelle | Docker + docker-compose.yml |
| **Tests** | Aucun | pytest + pytest-asyncio (test_detection.py, test_scoring.py) |
| **Logging** | `print()` | Loguru avec rotation de fichiers |
| **Configuration** | `config.cfg` hardcode | Pydantic Settings + `.env` + `rules.yaml` |
| **Scoring** | Score brut normalise | Score pondere : heuristique (60%) + ML (30%) + threat intel (10%) |
| **Linting** | Aucun | Ruff + mypy (type checking strict) |
| **Graph API** | Synchrone, sans pagination | Async, avec pagination et scan differentiel (parametre `since`) |

---

## Etapes de developpement

### Etape 1 : Enregistrement de l'application Azure AD

On a cree une **App Registration** dans Microsoft Entra ID (anciennement Azure AD).

- **Portail** : portal.azure.com -> Entra ID -> Inscriptions d'applications
- **Nom de l'app** : `PhishingDetectionAgent`
- **Type** : Single tenant (comptes de cette organisation uniquement)
- **Permissions** : `Mail.Read` + `User.Read.All` (Application, pas Delegated)
- **Admin consent** : accorde par l'administrateur

> **Piege rencontre** : ne pas confondre le "Secret ID" avec la "Value" du secret. Le Secret ID est inutile -- c'est la **Value** qu'il faut copier, et elle n'est affichee **qu'une seule fois**.

### Etape 2 : Premier test d'authentification

On a valide que le token OAuth2 etait correctement obtenu et que l'API Graph repondait.

> **Erreur rencontree** : `403 Authorization_RequestDenied` -- il manquait la permission `User.Read.All` en mode Application. Solution : ajouter la permission et accorder le consentement admin.

### Etape 3 : Acces aux boites mail

On a etendu `graph.py` pour recuperer les messages d'un utilisateur, incluant les `internetMessageHeaders` qui contiennent les resultats SPF/DKIM/DMARC.

> **Erreur rencontree** : `401 Unauthorized` sur les mails -- le tenant Azure for Students n'incluait pas de licence Exchange Online. Solution : migration vers un essai gratuit Microsoft 365 Business Basic (30 jours).

> **Piege rencontre** : les comptes externes (#EXT#) n'ont pas de boite mail dans le tenant. Il faut scanner uniquement les utilisateurs natifs du tenant (UPN en `@domaine.onmicrosoft.com`).

### Etape 4 : Integration du moteur de detection

On a adapte le `MoteurDetection` existant pour fonctionner avec les donnees provenant de Graph API au lieu de fichiers `.eml` :

- **Ajout** : verification SPF/DKIM/DMARC depuis les headers `Authentication-Results`
- **Ajout** : detection des TLD exotiques (.xyz, .top, .buzz...)
- **Ajout** : verification des doubles extensions sur les pieces jointes
- **Conservation** : toutes les regles existantes (Reply-To, URLs, mots-cles)
- **Ajout** : mots-cles en anglais (verify, confirm, suspended...)

### Etape 5 : Export et reporting

Le module `exporters.py` a ete entierement reecrit :

- **Console** : affichage resume avec stats (total, phishing, suspects, taux de detection)
- **CSV** : compatible Excel (separateur `;`, encodage UTF-8 BOM)
- **JSON** : structure complete avec summary + details pour traitement automatise
- **Serveur** : envoi HTTP POST au serveur Linux en temps reel

### Etape 6 : Deploiement du serveur Linux

On a deploye un serveur **FastAPI** sur une machine Linux interne (192.168.237.133) :

- **Base de donnees** : SQLite avec deux tables (scans + detections)
- **API REST** : endpoints pour recevoir, consulter et analyser les resultats
- **Service systemd** : le serveur tourne en permanence et redemarre automatiquement
- **Documentation** : Swagger UI accessible sur `http://IP:8000/docs`

### Etape 7 : Automatisation

Un script `auto_scan.py` non-interactif permet l'execution automatique via le **Planificateur de taches Windows**. Le scan tourne tous les jours, scanne toutes les boites, et envoie les resultats au serveur.

### Etape 8 : Refactoring V3

Refonte complete de l'architecture pour la production :

- Passage a Python 3.11+ avec async/await
- CLI moderne avec Typer + Rich
- Regles de detection externalisees en YAML
- ORM SQLAlchemy avec 5 modeles
- Tests unitaires avec pytest
- Containerisation Docker
- Scheduler integre APScheduler

---

## Prerequis

### Agent Windows (V2)

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.10+ | [python.org](https://python.org) |
| azure-identity | derniere | `pip install azure-identity` |
| msgraph-sdk | derniere | `pip install msgraph-sdk` |
| requests | derniere | `pip install requests` |

### Agent V3

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.11+ | [python.org](https://python.org) |
| Toutes deps | voir pyproject.toml | `pip install -e .` |
| Docker (optionnel) | derniere | [docker.com](https://docker.com) |

### Serveur Linux

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.10+ | `sudo apt install python3 python3-pip python3-venv` |
| FastAPI | 0.115+ | `pip install fastapi` |
| Uvicorn | 0.30+ | `pip install uvicorn` |

### Azure / Microsoft 365

| Composant | Detail |
|-----------|--------|
| Tenant Microsoft 365 | Business Basic minimum (avec Exchange Online) |
| Role | Administrateur Global (pour creer l'App Registration) |
| Permissions Graph API | `Mail.Read` + `User.Read.All` (Application) |
| Admin consent | Obligatoire |

---

## Installation et execution

### 1. Cloner le repo

```bash
git clone https://github.com/f3n999/SEC-TOPCHRONO.git
cd SEC-TOPCHRONO
```

### 2. Configurer les credentials Azure

**Methode V2** -- Creer un fichier `config.cfg` a la racine :

```ini
[azure]
clientId = VOTRE_CLIENT_ID
clientSecret = VOTRE_CLIENT_SECRET
tenantId = VOTRE_TENANT_ID
```

**Methode V3** -- Creer un fichier `.env` dans `V3/v3/` :

```env
AZURE_CLIENT_ID=votre_client_id
AZURE_CLIENT_SECRET=votre_client_secret
AZURE_TENANT_ID=votre_tenant_id
DATABASE_URL=sqlite+aiosqlite:///data/phishing_agent.db
PHISHING_SERVER=http://192.168.237.133:8000
SCAN_DEFAULT_EMAILS=25
SCAN_MAX_EMAILS=100
SCAN_INTERVAL_MINUTES=60
RULES_FILE=config/rules.yaml
LOG_LEVEL=INFO
```

> Ne jamais commit `config.cfg` ou `.env`. Ils sont dans le `.gitignore`.

### 3. Installer et lancer l'agent V2

```bash
cd files/
pip install azure-identity msgraph-sdk requests
python agent.py
```

### 4. Installer et lancer l'agent V3

```bash
cd V3/v3/
pip install -e .
# OU
pip install -e ".[dev]"    # avec outils de dev (pytest, ruff, mypy)
```

### 5. Deployer le serveur Linux

```bash
# Copier les fichiers sur la machine Linux
scp SRV/server.py SRV/deploy.sh SRV/requirements.txt user@192.168.237.133:/tmp/

# Se connecter en SSH
ssh user@192.168.237.133

# Lancer le deploiement automatique
chmod +x /tmp/deploy.sh
sudo bash /tmp/deploy.sh
```

### 6. Verifier le serveur

```bash
curl http://192.168.237.133:8000/api/health
# Reponse attendue : {"status":"ok","db":"connected"}
```

### 7. Deployer avec Docker (V3)

```bash
cd V3/v3/docker/
docker-compose up -d
```

---

## Configuration Azure AD

### Pas a pas

1. Aller sur **portal.azure.com**
2. Chercher **"Inscriptions d'applications"** (ou "App registrations")
3. Cliquer **"+ Nouvelle inscription"**
   - Nom : `PhishingDetectionAgent`
   - Type : Comptes dans cet annuaire uniquement
   - URI de redirection : vide
4. **Page Overview** -- copier :
   - `ID d'application (client)` -> c'est le `clientId`
   - `ID de l'annuaire (locataire)` -> c'est le `tenantId`
5. **Certificats & secrets -> + Nouveau secret client**
   - Copier la colonne **"Valeur"** immediatement (pas le "ID du secret")
   - Elle n'est affichee qu'une seule fois
6. **API autorisees -> + Ajouter une autorisation**
   - Microsoft Graph -> Autorisations d'application
   - Cocher `Mail.Read` et `User.Read.All`
   - Cliquer **"Accorder un consentement d'administrateur"**
   - Verifier que les deux permissions sont en vert

---

## Utilisation - Toutes les commandes

### V2 -- Mode interactif (dev / demo)

```bash
cd files/
python agent.py
```

```
==================================================
  PHISHING DETECTION AGENT v2.0
  Microsoft Graph API + Moteur Heuristique
==================================================

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
| **1** | Verifie que l'authentification OAuth2 fonctionne |
| **2** | Liste tous les utilisateurs du tenant avec leur UPN et mail |
| **3** | Scan rapide : analyse les 10 derniers mails d'un utilisateur |
| **4** | Scan complet : toutes les boites, genere CSV + JSON, envoie au serveur |

### V2 -- Mode automatique (production)

```bash
cd files/
python auto_scan.py
```

Ce script scanne automatiquement **tous les utilisateurs** sans intervention. Concu pour le Planificateur de taches Windows.

### V3 -- CLI moderne (Typer)

```bash
cd V3/v3/

# Scan standard (tous les utilisateurs, 25 derniers mails)
python -m src.cli scan

# Scanner un utilisateur specifique
python -m src.cli scan --user user@domain.com

# Scanner les 50 derniers emails par boite
python -m src.cli scan --top 50

# Scan rapide (sans export fichier)
python -m src.cli scan --quick

# Sans export fichier
python -m src.cli scan --no-export

# Sans envoi au serveur distant
python -m src.cli scan --no-server

# Combinaison
python -m src.cli scan --user admin@topchrono.onmicrosoft.com --top 100 --no-server
```

### V3 -- Lancer le serveur API local

```bash
cd V3/v3/
uvicorn src.api.server:app --host 0.0.0.0 --port 8080 --reload
# Swagger UI : http://localhost:8080/docs
```

### Serveur Linux -- Commandes de gestion

```bash
# Demarrer / Arreter / Redemarrer
sudo systemctl start phishing-server
sudo systemctl stop phishing-server
sudo systemctl restart phishing-server

# Voir le statut
sudo systemctl status phishing-server

# Voir les logs en temps reel
sudo journalctl -u phishing-server -f

# Activer au demarrage
sudo systemctl enable phishing-server
```

### Consulter les resultats

```bash
# Stats globales
curl http://192.168.237.133:8000/api/stats

# Emails phishing uniquement
curl "http://192.168.237.133:8000/api/detections?niveau=HIGH"

# Details du scan #1
curl http://192.168.237.133:8000/api/scans/1

# Tous les derniers scans
curl http://192.168.237.133:8000/api/scans

# Acces direct a la base SQLite (sur le serveur Linux)
sqlite3 /opt/phishing-server/phishing_agent.db "SELECT * FROM detections WHERE niveau='HIGH';"
```

### Lancer les tests (V3)

```bash
cd V3/v3/
pip install -e ".[dev]"
pytest tests/ -v
```

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
    -> [haute] Multiples mots-cles phishing (12) : urgent, activite suspecte...
----------------------------------------------------------------------
```

---

## Rendre le systeme persistant

### 1. Windows -- Planificateur de taches (V2)

Le fichier `files/run_scan.bat` lance le scan automatiquement :

```bat
@echo off
cd /d "C:\chemin\vers\AGENT-PY\files"
python auto_scan.py
```

**Etapes pour configurer :**

1. Ouvrir **Planificateur de taches** (taskschd.msc)
2. **Action** -> Creer une tache de base
3. **Nom** : `Phishing Detection Scan`
4. **Declencheur** : Tous les jours a 08h00
5. **Action** : Demarrer un programme -> pointer vers `run_scan.bat`
6. **Conditions** : Cocher "Executer meme si l'utilisateur n'est pas connecte"
7. **Parametres** : Cocher "Si la tache echoue, redemarrer toutes les 10 min"

> Le scan non-interactif (`auto_scan.py`) scanne toutes les boites et envoie les resultats au serveur Linux automatiquement.

### 2. Linux -- Service systemd (Serveur API)

Le script `SRV/deploy.sh` cree automatiquement le service systemd. Voici ce qu'il installe :

```ini
# /etc/systemd/system/phishing-server.service

[Unit]
Description=Phishing Detection API Server
After=network.target

[Service]
Type=simple
User=<votre_user>
WorkingDirectory=/opt/phishing-server
Environment=DB_PATH=/opt/phishing-server/phishing_agent.db
ExecStart=/opt/phishing-server/venv/bin/python /opt/phishing-server/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Ce que fait ce service :**
- Demarre automatiquement au boot du serveur (`enable`)
- Redemarre automatiquement en cas de crash (`Restart=always`, delai 5s)
- Lance le serveur FastAPI sur le port 8000
- Stocke la base SQLite dans `/opt/phishing-server/phishing_agent.db`

**Commandes de gestion :**

```bash
sudo systemctl status phishing-server    # Voir le statut
sudo systemctl restart phishing-server   # Redemarrer
sudo systemctl stop phishing-server      # Arreter
sudo systemctl enable phishing-server    # Activer au boot
sudo systemctl disable phishing-server   # Desactiver au boot
sudo journalctl -u phishing-server -f    # Logs en temps reel
sudo journalctl -u phishing-server --since "1 hour ago"  # Logs derniere heure
```

### 3. V3 -- APScheduler (scheduling integre Python)

Dans V3, le scheduling est integre directement dans l'application Python via APScheduler (`V3/v3/src/scheduler/jobs.py`) :

- **Scan automatique** via cron APScheduler (pas besoin de Task Scheduler externe)
- **Intervalle configurable** via `SCAN_INTERVAL_MINUTES` dans le `.env` (defaut : 60 min)
- **Scans differentiels** : ne re-scanne pas les emails deja analyses (parametre `since`)
- **Demarrage** : le scheduler se lance avec l'application

### 4. Docker -- Persistence avec volumes

```bash
cd V3/v3/docker/
docker-compose up -d
```

Le `docker-compose.yml` monte des volumes pour persister :
- La base de donnees SQLite
- Les fichiers de configuration
- Les logs

---

## Moteur de detection

### Regles heuristiques (14 regles en V2 / 6 modules en V3)

| # | Categorie | Verification | Severite | Points |
|---|-----------|-------------|----------|--------|
| 1 | Auth Headers | SPF FAIL | Haute | +40 |
| 2 | Auth Headers | SPF SOFTFAIL | Moyenne | +20 |
| 3 | Auth Headers | DKIM FAIL | Haute | +40 |
| 4 | Auth Headers | DMARC FAIL | Haute | +40 |
| 5 | Expediteur | Reply-To different du From | Haute | +40 |
| 6 | Expediteur | Domaine suspect (tirets/chiffres excessifs) | Moyenne | +20 |
| 7 | Expediteur | TLD exotique (.xyz, .top, .buzz, .tk...) | Moyenne | +20 |
| 8 | URLs | URL avec adresse IP au lieu de domaine | Haute | +40 |
| 9 | URLs | URL raccourcie (bit.ly, tinyurl...) | Moyenne | +20 |
| 10 | URLs | HTTP non securise (pas HTTPS) | Faible | +5 |
| 11 | Mots-cles | 2 mots-cles phishing detectes | Moyenne | +20 |
| 12 | Mots-cles | 3+ mots-cles phishing detectes | Haute | +40 |
| 13 | Pieces jointes | Extension dangereuse (.exe, .bat, .ps1...) | Haute | +40 |
| 14 | Pieces jointes | Double extension (document.pdf.exe) | Haute | +40 |

**Nouveau en V3 :**

| # | Categorie | Verification | Severite | Points |
|---|-----------|-------------|----------|--------|
| 15 | Homoglyphes | Substitution de caracteres (0->o, 1->l, @->a) | Haute | +40 |

### Systeme de scoring

| Plage | Niveau | Action | Interpretation |
|-------|--------|--------|----------------|
| 0-30 | **LOW** | ALLOW | Email probablement legitime |
| 31-60 | **MEDIUM** | REVIEW | Suspect -- verification humaine recommandee |
| 61-100 | **HIGH** | BLOCK | Phishing probable -- multiples indicateurs |

**V3 -- Scoring pondere :**
- Score heuristique : **60%** du poids total
- Score ML (optionnel) : **30%** du poids total
- Score Threat Intel (optionnel) : **10%** du poids total

### Mots-cles detectes (100+ termes, 8 categories)

| Categorie | Exemples |
|-----------|----------|
| **Urgence** | urgent, action requise, dernier delai, avant minuit, depechez-vous |
| **Compte compromis** | compte bloque, activite suspecte, suspension imminente, acces non autorise |
| **Donnees personnelles** | mot de passe, coordonnees bancaires, code pin, numero de carte, CVV |
| **Appels a l'action** | cliquez ici, verifiez, connectez-vous ici, telechargez maintenant |
| **Gains / loterie** | vous avez gagne, cadeau gratuit, offre exclusive, loterie |
| **Finance** | virement urgent, facture impayee, mise en demeure, huissier |
| **Usurpation** | service client, votre banque, police nationale, amazon, paypal |
| **Anglais** | verify your account, confirm your identity, unusual activity, dear customer |

### Configuration YAML des regles (V3)

En V3, toutes les regles sont configurables sans modifier le code, via `V3/v3/config/rules.yaml` :

```yaml
scoring:
  haute: 40
  moyenne: 20
  faible: 5

whitelist:
  domains:
    - "topchrono.com"
    - "microsoft.com"
    - "outlook.com"
    - "gmail.com"

suspicious_tlds:
  - "xyz"
  - "top"
  - "buzz"
  - "tk"
  - "ml"
  - "ru"
  - "cn"

thresholds:
  keywords_high: 3
  keywords_medium: 2
  domain_hyphens: 2
  domain_digits: 3
```

---

## API Serveur (endpoints)

Le serveur Linux expose une **API REST** documentee via Swagger UI.

**Documentation interactive** : `http://192.168.237.133:8000/docs`

| Methode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/api/health` | Verifie que le serveur et la DB fonctionnent |
| `POST` | `/api/scan` | Recoit un batch de resultats de scan |
| `GET` | `/api/scans` | Liste les derniers scans (avec pagination, defaut: 20) |
| `GET` | `/api/scans/{id}` | Details d'un scan avec toutes les detections |
| `GET` | `/api/stats` | Statistiques globales (totaux, tendances, top domaines) |
| `GET` | `/api/detections` | Liste les detections, filtrable par niveau |
| `GET` | `/docs` | Documentation Swagger UI interactive |
| `GET` | `/redoc` | Documentation ReDoc |

### Format du POST /api/scan

```json
{
  "agent_id": "agent-windows-01",
  "scan_date": "2026-03-26T08:00:00",
  "results": [
    {
      "boite": "admin@topchrono.onmicrosoft.com",
      "date": "2026-03-26T07:30:00",
      "expediteur": "security@fake-bank.xyz",
      "sujet": "URGENT - Votre compte sera ferme",
      "spf": "FAIL",
      "dkim": "FAIL",
      "dmarc": "FAIL",
      "reply_to_mismatch": true,
      "score": 100,
      "niveau": "HIGH",
      "action": "BLOCK",
      "anomalies": ["SPF FAIL", "DKIM FAIL", "DMARC FAIL", "12 mots-cles phishing"]
    }
  ]
}
```

---

## Schema de la base de donnees

```sql
-- Table des scans (1 ligne par execution de l'agent)
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

-- Table des detections (1 ligne par email analyse)
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

-- Index pour les performances
CREATE INDEX idx_detections_niveau ON detections(niveau);
CREATE INDEX idx_detections_scan ON detections(scan_id);
CREATE INDEX idx_scans_date ON scans(scan_date);
```

### V3 -- Modeles ORM SQLAlchemy (5 tables)

| Modele | Description |
|--------|-------------|
| `ScanSession` | 1 ligne par execution (session_id, timestamps, compteurs) |
| `ScanResultRow` | 1 ligne par email (message_id, sender, subject, tous les tests, anomalies JSON) |
| `WhitelistEntry` | Domaines/emails/IPs de confiance avec raison |
| `ThreatIndicator` | Cache d'URLs/domaines/IPs suspects avec compteur de hits |
| `BaselineData` | Donnees de reference pour calibration |

---

## Structure du projet

```
SEC-TOPCHRONO/
│
├── config.cfg                         # Credentials Azure (NE PAS COMMIT)
├── .gitignore                         # Fichiers exclus du repo
├── README.md                          # Ce fichier
├── agent.py                           # V1 - Script de base (prototypage)
├── graph.py                           # V1 - Client Graph API basique
│
├── files/                             # V2 - CODE PRODUCTION (Windows)
│   ├── agent.py                       # Menu interactif (4 options)
│   ├── auto_scan.py                   # Scan automatique (Task Scheduler)
│   ├── graph.py                       # Client Microsoft Graph API
│   ├── detection_rules.py             # Moteur heuristique (14 regles, 100+ mots-cles)
│   ├── risk_scorer.py                 # Scoring 0-100 + niveaux LOW/MEDIUM/HIGH
│   ├── exporters.py                   # Export CSV + JSON + Console + envoi serveur
│   └── run_scan.bat                   # Lanceur pour Windows Task Scheduler
│
├── SRV/                               # SERVEUR LINUX (192.168.237.133)
│   ├── server.py                      # FastAPI + SQLite (6 endpoints)
│   ├── deploy.sh                      # Installation auto + creation service systemd
│   └── requirements.txt              # Dependances serveur (fastapi, uvicorn, pydantic)
│
├── V3/                                # V3 - REFACTORING COMPLET
│   ├── v3-conception/                 # Documents d'architecture V3
│   │   ├── ARCHITECTURE-V3.md        # Schema technique detaille
│   │   ├── QUICK-WINS.md             # Ameliorations rapides V2
│   │   └── ANALYSE-V2-ET-ROADMAP-V3.md  # Analyse + feuille de route
│   │
│   └── v3/                            # Code V3 production
│       ├── pyproject.toml             # Config projet Python moderne
│       ├── .env.example               # Template de configuration
│       │
│       ├── config/
│       │   ├── rules.yaml             # Regles de detection (YAML configurable)
│       │   └── settings.py            # Pydantic Settings (validation .env)
│       │
│       ├── docker/
│       │   ├── Dockerfile             # Image container
│       │   └── docker-compose.yml     # Orchestration Docker
│       │
│       ├── src/
│       │   ├── cli.py                 # CLI Typer (scan --user --top --quick)
│       │   │
│       │   ├── api/                   # Serveur API integre
│       │   │   ├── server.py          # FastAPI app + lifespan
│       │   │   └── routes/
│       │   │       ├── health.py      # GET /health
│       │   │       ├── scan.py        # POST /api/scan
│       │   │       └── reports.py     # GET /api/reports
│       │   │
│       │   ├── core/                  # Coeur de l'application
│       │   │   ├── graph_client.py    # Client Graph API async + pagination
│       │   │   ├── scanner.py         # Orchestrateur de scan
│       │   │   └── logger.py          # Loguru configuration
│       │   │
│       │   ├── detection/             # Moteur de detection modulaire
│       │   │   ├── engine.py          # Orchestrateur + chargement YAML
│       │   │   └── rules/
│       │   │       ├── auth_headers.py    # SPF / DKIM / DMARC
│       │   │       ├── sender.py          # Validation domaine expediteur
│       │   │       ├── urls.py            # Analyse URLs (IP, shorteners, HTTP)
│       │   │       ├── keywords.py        # Mots-cles phishing (8 categories)
│       │   │       ├── attachments.py     # Extensions dangereuses
│       │   │       └── homoglyphs.py      # Detection substitution caracteres
│       │   │
│       │   ├── scoring/
│       │   │   └── risk_scorer.py     # Score pondere (heuristique 60% + ML 30% + TI 10%)
│       │   │
│       │   ├── db/                    # Persistence
│       │   │   ├── database.py        # SQLAlchemy async init
│       │   │   ├── models.py          # 5 modeles ORM
│       │   │   └── repository.py      # Data access layer (CRUD)
│       │   │
│       │   ├── export/                # Formats de sortie
│       │   │   ├── console.py         # Affichage Rich (tableaux, couleurs)
│       │   │   ├── json_export.py     # Export JSON structure
│       │   │   ├── csv_export.py      # Export CSV (Excel-compatible)
│       │   │   └── api_export.py      # Envoi HTTP vers serveur distant
│       │   │
│       │   └── scheduler/
│       │       └── jobs.py            # APScheduler (cron scans automatiques)
│       │
│       └── tests/
│           ├── conftest.py            # Fixtures pytest
│           ├── test_detection.py      # Tests moteur de detection
│           └── test_scoring.py        # Tests scoring
│
├── conception/                        # Documents de conception
├── conception-agent.docx              # Document de conception technique
├── figma.txt                          # Lien vers diagramme FigJam
├── lien important.txt                 # Liens documentation Microsoft
└── Python avec Microsoft.txt          # Notes tutoriel Graph API
```

---

## References et documentation

### Documentation officielle Microsoft

| Ressource | URL |
|-----------|-----|
| Tutoriel Python Graph API (app-only) | https://learn.microsoft.com/en-us/graph/tutorials/python-app-only |
| Flux OAuth2 Client Credentials | https://learn.microsoft.com/en-us/graph/auth-v2-service |
| Trouver le Tenant ID | https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant |
| API Messages Graph | https://learn.microsoft.com/en-us/graph/api/user-list-messages |
| Concepts Auth Graph | https://learn.microsoft.com/en-us/graph/auth/auth-concepts |

### References cybersecurite

| Source | Utilisation |
|--------|------------|
| Verizon DBIR | Statistiques sur les vecteurs d'attaque (91% phishing) |
| IBM Cost of a Data Breach | Cout moyen des incidents (45 000 euros) |
| ANSSI | Recommandations securite email |

### Livrables du projet

| Document | Description |
|----------|-------------|
| `conception-agent.docx` | Document de conception technique complet |
| `V3/v3-conception/ARCHITECTURE-V3.md` | Architecture technique V3 |
| `V3/v3-conception/ANALYSE-V2-ET-ROADMAP-V3.md` | Analyse V2 + feuille de route V3 |
| `V3/v3-conception/QUICK-WINS.md` | Ameliorations rapides |
| Diagramme FigJam | Architecture detaillee (lien dans `figma.txt`) |

### Stack technique V3

| Composant | Technologie | Justification |
|-----------|------------|---------------|
| Runtime | Python 3.11+ | Compatibilite Graph SDK |
| CLI | Typer | Moderne, type hints, auto-complete |
| API | FastAPI | Async natif, OpenAPI auto, validation |
| ORM | SQLAlchemy 2.0 | Async support, mature |
| DB | SQLite / PostgreSQL | SQLite dev, Postgres prod |
| Scheduler | APScheduler | Leger, cron + interval |
| Config | Pydantic Settings | Validation, .env, type-safe |
| Logging | loguru | Simple, colore, rotation |
| Tests | pytest + pytest-asyncio | Standard Python |
| Lint | ruff | Ultra rapide, remplace flake8+isort+black |
| Types | mypy | Securite type statique |
| Container | Docker + Compose | Deploiement standardise |

---

## Equipe

Ce projet est developpe par une equipe de 4 personnes dans le cadre d'un projet de securite informatique.

| Membre | Role |
|--------|------|
| **Mohamed Elnaggar** | Backend API, deploiement serveur, moteur de detection, architecture V3 |
| **Membre 2** | A completer |
| **Membre 3** | A completer |
| **Membre 4** | A completer |

---

## Axes d'amelioration

### Court terme (v1.5 -- Quick wins)

- [ ] Dashboard web interactif pour visualiser les stats
- [ ] Alertes email automatiques quand un phishing est detecte
- [ ] Scan du corps des emails (avec opt-in conformite)
- [ ] Enrichissement des domaines via WHOIS (date de creation, registrar)
- [ ] Analyse des pieces jointes (hash, type MIME)

### Moyen terme (v2.0 -- Integration Defender)

- [ ] Deploiement de Microsoft Defender for Office 365 (Threat Explorer)
- [ ] Correlation des donnees de l'agent avec Defender
- [ ] Machine Learning sur les patterns de phishing detectes
- [ ] Integration SIEM (Microsoft Sentinel)
- [ ] API d'enrichissement via MISP (Threat Intelligence)
- [ ] Integration VirusTotal, AbuseIPDB, PhishTank

### Long terme (v3.0 -- Maturite)

- [ ] Campagnes de simulation de phishing internes
- [ ] Module de formation et sensibilisation des utilisateurs
- [ ] Reporting mensuel automatise pour la DSI
- [ ] Score de maturite securite de l'organisation
- [ ] Extension a d'autres vecteurs (Teams, SharePoint)

---

## Avertissements

- **Conformite RGPD** : L'agent ne collecte que les metadonnees techniques (expediteur, sujet, headers). Le corps des emails et les pieces jointes ne sont pas lus. Validation DPO requise avant deploiement production.
- **Credentials** : Ne jamais commit le fichier `config.cfg` ou `.env`. Utiliser des variables d'environnement en production.
- **Scope** : L'agent est un outil de **mesure**, pas de **protection**. Il ne bloque, ne supprime, et ne modifie aucun email.
- **Permissions** : `Mail.Read` en mode Application donne acces en lecture a **toutes les boites mail** du tenant. Admin consent requis.
- **Secret Azure** : La valeur du secret client n'est affichee qu'une seule fois lors de la creation. La sauvegarder immediatement.

---

## Chiffres cles

| Metrique | Valeur |
|----------|--------|
| Fichiers Python | ~30 |
| Lignes de code (V3) | ~5 284 |
| Regles de detection | 15 (14 heuristiques + homoglyphes) |
| Mots-cles phishing | 100+ (FR/EN, 8 categories) |
| TLDs suspects configures | 13 |
| Extensions dangereuses | 13 |
| Endpoints API | 6 + Swagger |
| Modeles DB (V3) | 5 |
| Tests unitaires | 2 fichiers (detection + scoring) |
| Repository | github.com/f3n999/SEC-TOPCHRONO |

---

## Licence

MIT License -- voir [LICENSE](LICENSE) pour les details.

---

*Phishing Detection Agent -- SEC-TOPCHRONO -- De la V1 a la V3, brique par brique.*
