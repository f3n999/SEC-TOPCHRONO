"""Chargement des clés API depuis config/secrets.yaml."""
import os
from pathlib import Path

import yaml

_SECRETS_FILE = Path(__file__).parent.parent.parent / "config" / "secrets.yaml"
_cache: dict = {}


def _load() -> dict:
    global _cache
    if _cache:
        return _cache
    if _SECRETS_FILE.exists():
        with open(_SECRETS_FILE, encoding="utf-8") as f:
            _cache = yaml.safe_load(f) or {}
    return _cache


def get(key: str, env_fallback: str = "") -> str:
    """Retourne la clé API : secrets.yaml en priorité, puis variable d'environnement."""
    value = _load().get(key, "")
    if not value and env_fallback:
        value = os.environ.get(env_fallback, "")
    return value
