"""
Moteur de detection v3.0
Charge les regles depuis YAML, orchestre les modules de detection.
"""
import yaml
from pathlib import Path
from loguru import logger

from src.detection.rules.auth_headers import check_auth_headers
from src.detection.rules.sender import check_sender
from src.detection.rules.urls import check_urls
from src.detection.rules.keywords import check_keywords
from src.detection.rules.attachments import check_attachments
from src.detection.rules.homoglyphs import check_homoglyphs


class DetectionEngine:
    """Moteur de detection orchestrant toutes les regles."""

    def __init__(self, rules_file: str = "config/rules.yaml"):
        self.rules = self._load_rules(rules_file)
        self.scores = self.rules.get("scoring", {"haute": 40, "moyenne": 20, "faible": 5})
        self.whitelist_domains = set(self.rules.get("whitelist", {}).get("domains", []))
        self.blacklist_domains = set(self.rules.get("blacklist", {}).get("domains", []))
        logger.info(
            "Moteur charge : {} domaines whitelist, {} regles keywords",
            len(self.whitelist_domains),
            sum(len(v) for v in self.rules.get("keywords", {}).values()),
        )

    def _load_rules(self, rules_file: str) -> dict:
        """Charge les regles depuis un fichier YAML."""
        path = Path(rules_file)
        if not path.exists():
            logger.warning("Fichier de regles {} introuvable, utilisation des defauts", rules_file)
            return {}
        with open(path, encoding="utf-8") as f:
            rules = yaml.safe_load(f) or {}
        logger.debug("Regles chargees depuis {}", rules_file)
        return rules

    def is_whitelisted(self, email_address: str) -> bool:
        """Verifie si l'expediteur est dans la whitelist."""
        if not email_address or "@" not in email_address:
            return False
        domain = email_address.split("@")[-1].lower()
        return domain in self.whitelist_domains

    def is_blacklisted(self, email_address: str) -> bool:
        """Verifie si l'expediteur est dans la blacklist."""
        if not email_address or "@" not in email_address:
            return False
        domain = email_address.split("@")[-1].lower()
        return domain in self.blacklist_domains

    def analyser(self, email_data: dict) -> list[dict]:
        """
        Analyse un email et retourne les anomalies detectees.
        Chaque anomalie = {"severite": str, "description": str, "score": int, "rule": str}
        """
        expediteur = email_data.get("expediteur", "")

        # Whitelist : skip l'analyse
        if self.is_whitelisted(expediteur):
            return []

        # Blacklist : flag immediat
        if self.is_blacklisted(expediteur):
            return [self._anomalie("haute", f"Domaine blackliste : {expediteur}", "blacklist")]

        anomalies = []

        # Executer chaque module de detection
        anomalies.extend(check_auth_headers(email_data, self.scores))
        anomalies.extend(check_sender(email_data, self.rules, self.scores))
        anomalies.extend(check_urls(email_data, self.rules, self.scores))
        anomalies.extend(check_keywords(email_data, self.rules, self.scores))
        anomalies.extend(check_attachments(email_data, self.rules, self.scores))
        anomalies.extend(check_homoglyphs(email_data, self.scores))

        return anomalies

    def _anomalie(self, severite: str, description: str, rule: str) -> dict:
        return {
            "severite": severite,
            "description": description,
            "score": self.scores.get(severite, 0),
            "rule": rule,
        }
