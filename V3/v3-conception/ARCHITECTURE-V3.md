# Architecture V3 - Schema technique

## Vue d'ensemble

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
  │ MS Graph API│ │ Regles      │ │ Poids       │
  │ - Users     │ │ dynamiques  │ │ configurables│
  │ - Messages  │ │ (YAML)      │ │ Score 0-100 │
  │ - Headers   │ │             │ │ + ML boost  │
  │ - Webhooks  │ │ + ML Model  │ │             │
  └─────────────┘ │ (optionnel) │ └─────────────┘
                  └──────┬──────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
  │ AUTH        │ │ CONTENT     │ │ THREAT      │
  │ HEADERS     │ │ ANALYSIS    │ │ INTEL       │
  ├─────────────┤ ├─────────────┤ ├─────────────┤
  │ SPF/DKIM/   │ │ URLs        │ │ VirusTotal  │
  │ DMARC       │ │ Keywords    │ │ AbuseIPDB   │
  │ Received    │ │ Attachments │ │ PhishTank   │
  │ chain       │ │ Homoglyphes │ │ HIBP        │
  └─────────────┘ └─────────────┘ └─────────────┘
                         │
              ┌──────────▼──────────┐
              │    PERSISTENCE      │
              │  (SQLAlchemy + DB)  │
              ├─────────────────────┤
              │ - scan_sessions     │
              │ - scan_results      │
              │ - anomalies         │
              │ - threat_indicators │
              │ - whitelist         │
              └──────────┬──────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
  │ EXPORT      │ │ ALERTING    │ │ DASHBOARD   │
  ├─────────────┤ ├─────────────┤ ├─────────────┤
  │ JSON/CSV    │ │ Webhook     │ │ Stats API   │
  │ PDF         │ │ Email       │ │ Tendances   │
  │ REST API    │ │ Slack/Teams │ │ Top menaces │
  └─────────────┘ └─────────────┘ └─────────────┘
```

## Flux de donnees - Scan automatique

```
1. Scheduler declenche scan
       │
2. Scanner verifie dernier scan timestamp
       │
3. Graph Client recupere emails depuis last_scan_at
       │
4. Pour chaque email :
       ├── Detection Engine applique toutes les regles
       ├── Threat Intel verifie URLs/IPs (cache 24h)
       ├── ML Classifier predit probabilite phishing
       │
5. Risk Scorer combine :
       ├── Score heuristique (60% poids)
       ├── Score ML (30% poids)
       ├── Score Threat Intel (10% poids)
       │
6. Persistance en BDD
       │
7. Si score >= seuil HIGH :
       ├── Alerte webhook immediate
       ├── Email a l'admin
       └── Log securite
```

## Stack technique V3

| Composant | Technologie | Justification |
|-----------|------------|---------------|
| Runtime | Python 3.12+ | Compatibilite Graph SDK |
| CLI | Typer | Modern, type hints, auto-complete |
| API | FastAPI | Async natif, OpenAPI auto, validation |
| ORM | SQLAlchemy 2.0 | Async support, mature |
| DB | SQLite / PostgreSQL | SQLite dev, Postgres prod |
| Migrations | Alembic | Standard SQLAlchemy |
| Scheduler | APScheduler | Leger, cron + interval |
| Config | Pydantic Settings | Validation, .env, type-safe |
| Logging | loguru | Simple, colore, rotation |
| Tests | pytest + pytest-asyncio | Standard Python |
| Lint | ruff | Ultra rapide, remplace flake8+isort+black |
| Types | mypy | Securite type statique |
| Container | Docker + Compose | Deploiement standardise |
| CI | GitHub Actions | Gratuit, integre |
