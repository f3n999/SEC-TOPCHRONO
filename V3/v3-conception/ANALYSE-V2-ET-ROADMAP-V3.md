# Agent Phishing Detection - Analyse V2 & Roadmap V3

## Etat des lieux V2

### Architecture actuelle
```
files/
  agent.py          -> CLI menu + orchestration (312 lignes)
  graph.py          -> Client Microsoft Graph API (58 lignes)
  detection_rules.py -> Moteur heuristique (227 lignes)
  risk_scorer.py    -> Scoring risque 0-100 (49 lignes)
  exporters.py      -> Export console/JSON/CSV/REST (154 lignes)
```

### Points forts V2
- Architecture modulaire avec separation des responsabilites
- Async/await pour les appels Graph API
- Detection heuristique complete (195+ mots-cles, 8+ types d'anomalies)
- Export multi-format (console, JSON, CSV, REST API)
- Gestion des erreurs Graph API (401, 403, 404)

### Points faibles identifies

| # | Probleme | Impact | Priorite |
|---|----------|--------|----------|
| 1 | **Pas de persistance** - Aucune BDD, les resultats sont perdus entre les scans | Impossible de suivre l'evolution des menaces | CRITIQUE |
| 2 | **Detection 100% heuristique** - Pas de ML, beaucoup de faux positifs potentiels | Fatigue d'alerte pour les admins | HAUTE |
| 3 | **Pas de scan automatique** - Uniquement CLI manuelle, pas de scheduling | Pas de surveillance continue | HAUTE |
| 4 | **Aucun test unitaire** - 0 fichier de test | Regressions possibles a chaque modif | HAUTE |
| 5 | **Config en .cfg hardcode** - Pas de .env, pas de validation | Risque de fuite credentials | MOYENNE |
| 6 | **Pas de logging** - print() partout, pas de fichier de log | Debug difficile en production | MOYENNE |
| 7 | **Pas d'API REST propre** - L'agent envoie mais n'expose pas d'API | Impossible d'integrer avec d'autres outils | MOYENNE |
| 8 | **Fichiers V1 encore presents** - agent.py et graph.py a la racine | Confusion, code mort | BASSE |
| 9 | **Pas de requirements.txt/pyproject.toml** - Dependances non declarees | Installation non reproductible | HAUTE |
| 10 | **Pas de containerisation** - Ni Docker ni Docker Compose | Deploiement non standardise | MOYENNE |

---

## Roadmap V3 - Propositions d'ameliorations

### AXE 1 : Architecture & Structure projet

#### 1.1 Restructuration du projet
```
phishing-agent-v3/
  src/
    __init__.py
    cli.py                -> Interface CLI (Click/Typer)
    api/
      __init__.py
      server.py           -> FastAPI REST API
      routes/
        scan.py
        reports.py
        health.py
    core/
      __init__.py
      scanner.py          -> Orchestrateur de scan
      graph_client.py     -> Client Graph API
    detection/
      __init__.py
      engine.py           -> Moteur de detection principal
      rules/
        auth_headers.py   -> Regles SPF/DKIM/DMARC
        url_analysis.py   -> Analyse URLs
        keywords.py       -> Detection mots-cles
        attachments.py    -> Verification pieces jointes
        sender.py         -> Verification expediteur
      ml/
        classifier.py     -> Classificateur ML (optionnel)
        features.py       -> Extraction de features
    scoring/
      __init__.py
      risk_scorer.py      -> Scoring ameliore avec poids configurables
    export/
      __init__.py
      console.py
      json_export.py
      csv_export.py
      api_export.py
    db/
      __init__.py
      models.py           -> SQLAlchemy models
      repository.py       -> CRUD operations
      migrations/         -> Alembic migrations
    scheduler/
      __init__.py
      jobs.py             -> APScheduler jobs
  tests/
    __init__.py
    test_detection.py
    test_scoring.py
    test_graph.py
    test_exporters.py
    conftest.py           -> Fixtures pytest
  config/
    settings.py           -> Pydantic Settings
    .env.example
  docker/
    Dockerfile
    docker-compose.yml
  pyproject.toml
  README.md
```

#### 1.2 Gestion des dependances
- Migrer vers **pyproject.toml** (PEP 621)
- Utiliser **uv** ou **poetry** pour le lock file
- Separer deps de dev (pytest, ruff, mypy) et prod

#### 1.3 Configuration moderne
- **Pydantic Settings** pour validation des configs
- Fichier `.env` avec `.env.example` versionne
- Variables d'environnement pour tous les secrets

---

### AXE 2 : Detection & Intelligence

#### 2.1 Amelioration des regles heuristiques
- **Poids configurables** par regle (YAML/JSON externe)
- **Regles par categorie** avec activation/desactivation individuelle
- **Whitelisting** de domaines/expediteurs de confiance
- **Blacklisting** de domaines connus malveillants
- **Detection homoglyphes** (ex: paypa1.com vs paypal.com)
- **Analyse entetes complets** (X-Originating-IP, Received chain)

#### 2.2 Machine Learning (Phase 2)
- **Feature extraction** depuis les emails existants
- **Classificateur supervisae** (Random Forest / XGBoost) entraine sur les scans passes
- **Mode hybride** : heuristique + ML avec score combine
- **Feedback loop** : l'admin peut marquer un email comme faux positif/negatif

#### 2.3 Threat Intelligence
- Integration avec des bases de menaces :
  - **VirusTotal API** pour verifier les URLs/fichiers
  - **AbuseIPDB** pour les IPs suspectes
  - **PhishTank** pour les URLs de phishing connues
  - **Have I Been Pwned** pour les domaines compromis

---

### AXE 3 : Persistance & Historique

#### 3.1 Base de donnees
- **SQLite** (mode standalone) ou **PostgreSQL** (mode serveur)
- **SQLAlchemy** comme ORM
- **Alembic** pour les migrations

#### 3.2 Modele de donnees propose
```
scan_sessions
  id, started_at, finished_at, scan_type, users_scanned, emails_scanned

scan_results
  id, session_id, user_email, message_id, subject, sender
  risk_score, risk_level, anomalies_json, scanned_at

anomalies
  id, result_id, type, severity, description, rule_name

threat_indicators
  id, type (url/domain/ip/hash), value, first_seen, last_seen, hit_count

whitelist
  id, type (domain/email/ip), value, added_by, added_at, reason
```

#### 3.3 Dashboard & Reporting
- **Statistiques en temps reel** : emails scannes, menaces detectees, taux de phishing
- **Tendances** : evolution sur 7j/30j/90j
- **Top menaces** : expediteurs/domaines les plus suspects
- **Export PDF** de rapports periodiques

---

### AXE 4 : Automatisation & Monitoring

#### 4.1 Scan automatique
- **APScheduler** pour les scans programmas
- Modes : toutes les X minutes, quotidien, hebdomadaire
- Scan differentiel (uniquement les nouveaux emails depuis le dernier scan)

#### 4.2 Alertes temps reel
- **Webhook** : notification instantanee sur menace HIGH
- **Email d'alerte** a l'admin quand score > seuil
- **Integration Slack/Teams** pour les notifications
- **Microsoft Graph Subscriptions** pour recevoir les webhooks sur nouveaux emails

#### 4.3 API REST (FastAPI)
```
GET  /api/health              -> Status de l'agent
POST /api/scan/quick/{user}   -> Scan rapide d'un utilisateur
POST /api/scan/full           -> Scan complet
GET  /api/reports             -> Liste des rapports
GET  /api/reports/{id}        -> Detail d'un rapport
GET  /api/stats               -> Statistiques globales
GET  /api/threats             -> Indicateurs de menaces
POST /api/whitelist           -> Ajouter a la whitelist
```

---

### AXE 5 : Qualite & DevOps

#### 5.1 Tests
- **pytest** avec fixtures pour mocker Graph API
- **Coverage** > 80% sur le moteur de detection
- **Tests d'integration** avec des emails de test
- **Tests de regression** sur les faux positifs connus

#### 5.2 CI/CD
- **GitHub Actions** : lint (ruff) + type check (mypy) + tests + build
- **Pre-commit hooks** : formatting, linting
- **Semantic versioning** automatique

#### 5.3 Docker
```yaml
# docker-compose.yml
services:
  agent:
    build: .
    env_file: .env
    volumes:
      - ./data:/app/data
    ports:
      - "8080:8080"
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: phishing_agent
      POSTGRES_USER: agent
      POSTGRES_PASSWORD: ${DB_PASSWORD}

  scheduler:
    build: .
    command: python -m src.scheduler
    env_file: .env
    depends_on:
      - db
```

#### 5.4 Logging & Observabilite
- **structlog** ou **loguru** pour des logs structures
- Niveaux : DEBUG, INFO, WARNING, ERROR
- Rotation des fichiers de log
- **Metriques** : nombre de scans, temps de reponse, taux de detection

---

### AXE 6 : Securite

#### 6.1 Gestion des secrets
- **Jamais** de credentials dans le code ou git
- `.env` + `.env.example` (sans valeurs)
- Support Azure Key Vault pour production

#### 6.2 Securite API
- **JWT** ou **API Key** pour l'API REST
- Rate limiting
- CORS configure
- Input validation (Pydantic)

#### 6.3 Conformite
- Pas de stockage du contenu complet des emails (RGPD)
- Retention configurable des resultats de scan
- Logs d'audit des actions admin

---

## Plan de mise en oeuvre

### Phase 1 - Fondations (Semaine 1-2)
- [ ] Restructuration du projet (nouvelle arborescence)
- [ ] pyproject.toml + dependances
- [ ] Pydantic Settings pour la config
- [ ] Logging avec loguru
- [ ] Migration des modules existants
- [ ] Tests unitaires de base

### Phase 2 - Persistance & API (Semaine 3-4)
- [ ] SQLAlchemy models + Alembic migrations
- [ ] Repository pattern pour CRUD
- [ ] FastAPI avec endpoints de scan
- [ ] Scan differentiel (nouveaux emails uniquement)

### Phase 3 - Detection avancee (Semaine 5-6)
- [ ] Regles configurables (YAML)
- [ ] Whitelist/Blacklist
- [ ] Detection homoglyphes
- [ ] Integration VirusTotal (optionnel)

### Phase 4 - Automatisation (Semaine 7-8)
- [ ] APScheduler pour scans automatiques
- [ ] Alertes webhook/email
- [ ] Dashboard stats basique
- [ ] Docker + docker-compose

### Phase 5 - ML & Polish (Semaine 9-10)
- [ ] Feature extraction
- [ ] Classificateur ML basique
- [ ] Mode hybride heuristique + ML
- [ ] Documentation complete
- [ ] CI/CD GitHub Actions
