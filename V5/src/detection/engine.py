"""
Moteur de détection V5
Fix critique V4 : la whitelist ne court-circuite plus l'analyse URL.
Un expéditeur connu réduit le score mais les URLs sont toujours vérifiées.
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

    def __init__(self, rules_file: str = "config/rules.yaml"):
        self.rules = self._load_rules(rules_file)
        self.scores = self.rules.get("scoring", {"haute": 40, "moyenne": 20, "faible": 5})
        self.whitelist_domains = set(self.rules.get("whitelist", {}).get("domains", []))
        self.blacklist_domains = set(self.rules.get("blacklist", {}).get("domains", []))
        logger.info(
            "Moteur V5 chargé : {} domaines whitelist, {} règles keywords",
            len(self.whitelist_domains),
            sum(len(v) for v in self.rules.get("keywords", {}).values()),
        )

    def _load_rules(self, rules_file: str) -> dict:
        path = Path(rules_file)
        if not path.exists():
            logger.warning("Fichier de règles {} introuvable, utilisation des défauts", rules_file)
            return {}
        with open(path, encoding="utf-8") as f:
            rules = yaml.safe_load(f) or {}
        return rules

    def is_whitelisted(self, email_address: str) -> bool:
        if not email_address or "@" not in email_address:
            return False
        domain = email_address.split("@")[-1].lower()
        return domain in self.whitelist_domains

    def is_blacklisted(self, email_address: str) -> bool:
        if not email_address or "@" not in email_address:
            return False
        domain = email_address.split("@")[-1].lower()
        return domain in self.blacklist_domains

    def analyser(self, email_data: dict) -> list[dict]:
        """
        Analyse complète d'un email.

        FIX V5 : la whitelist ne stoppe plus l'analyse.
        Elle applique un bonus de score négatif (-20) sur le sender,
        mais les URLs sont TOUJOURS vérifiées.
        """
        expediteur = email_data.get("expediteur", "")
        anomalies = []

        # Blacklist : flag immédiat
        if self.is_blacklisted(expediteur):
            return [self._anomalie("haute", f"Domaine blacklisté : {expediteur}", "blacklist")]

        # Whitelist : on continue l'analyse mais on note la confiance sur le sender
        sender_trusted = self.is_whitelisted(expediteur)
        if sender_trusted:
            logger.debug("Expéditeur whitelisté ({}) — analyse URL maintenue", expediteur)
            # Bonus de confiance : réduit le score final via une "anomalie" négative
            anomalies.append({
                "severite": "bonus",
                "description": f"Expéditeur de confiance : {expediteur}",
                "score": -20,
                "rule": "whitelist_bonus",
            })

        # Tous les modules de détection tournent dans tous les cas
        anomalies.extend(check_auth_headers(email_data, self.scores))
        anomalies.extend(check_sender(email_data, self.rules, self.scores))
        anomalies.extend(check_urls(email_data, self.rules, self.scores, expediteur))
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
