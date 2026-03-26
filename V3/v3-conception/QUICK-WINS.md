# Quick Wins - Ameliorations rapides (1-2 jours chacune)

Ces ameliorations peuvent etre faites immediatement sur la V2 existante
avant de commencer la V3 complete.

## 1. Ajouter requirements.txt
```
azure-identity>=1.15.0
msgraph-sdk>=1.2.0
requests>=2.31.0
```
**Effort** : 10 min | **Impact** : Installation reproductible

## 2. Remplacer config.cfg par .env
```python
# Avant (configparser)
config = configparser.ConfigParser()
config.read('config.cfg')

# Apres (python-dotenv)
from dotenv import load_dotenv
import os
load_dotenv()
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
```
**Effort** : 30 min | **Impact** : Securite + standard

## 3. Ajouter logging basique
```python
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
```
**Effort** : 1h | **Impact** : Debug et audit

## 4. Supprimer les fichiers V1 a la racine
- Supprimer `agent.py` (racine) - remplace par `files/agent.py`
- Supprimer `graph.py` (racine) - remplace par `files/graph.py`
- Supprimer `files.zip` - redondant

**Effort** : 5 min | **Impact** : Clarte du projet

## 5. Ajouter whitelist de domaines
```python
TRUSTED_DOMAINS = [
    "topchrono.com",
    "microsoft.com",
    "office365.com",
    # ... domaines internes
]

def is_trusted_sender(email_address: str) -> bool:
    domain = email_address.split("@")[-1].lower()
    return domain in TRUSTED_DOMAINS
```
**Effort** : 1h | **Impact** : Reduction massive des faux positifs

## 6. Scan differentiel
```python
# Sauvegarder le timestamp du dernier scan
LAST_SCAN_FILE = "last_scan.json"

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE) as f:
            return json.load(f)["last_scan"]
    return None

# Filtrer les emails dans Graph API
filter_query = f"receivedDateTime ge {last_scan_time}"
```
**Effort** : 2h | **Impact** : Scans plus rapides, moins de doublons

## 7. Ajouter un mode --quiet / --verbose
```python
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-q', '--quiet', action='store_true')
parser.add_argument('-v', '--verbose', action='store_true')
```
**Effort** : 1h | **Impact** : Flexibilite d'utilisation

## 8. Detection des homoglyphes (quick version)
```python
HOMOGLYPHE_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '5': 's', '7': 't', '@': 'a'
}

def normalize_domain(domain: str) -> str:
    normalized = domain.lower()
    for fake, real in HOMOGLYPHE_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized
```
**Effort** : 1h | **Impact** : Detecte paypa1.com, g00gle.com, etc.
