"""Fixtures pytest pour les tests."""
import pytest


@pytest.fixture
def sample_email_clean():
    """Email legitime sans anomalie."""
    return {
        "message_id": "msg-001",
        "expediteur": "john@microsoft.com",
        "sujet": "Reunion hebdomadaire",
        "date": "2024-01-15T10:00",
        "reply_to": "",
        "originating_ip": "",
        "corps": "Bonjour, voici le compte rendu de la reunion.",
        "corps_html": "",
        "urls": [],
        "pieces_jointes": [],
        "spf": "PASS",
        "dkim": "PASS",
        "dmarc": "PASS",
    }


@pytest.fixture
def sample_email_phishing():
    """Email de phishing avec multiples indicateurs."""
    return {
        "message_id": "msg-002",
        "expediteur": "security@paypa1-verify.xyz",
        "sujet": "URGENT : Votre compte bloque - action requise immediatement",
        "date": "2024-01-15T08:30",
        "reply_to": "hacker@evil.tk",
        "originating_ip": "185.234.12.1",
        "corps": "Cher client, votre compte a ete suspendu. Cliquez ici pour verifier vos identifiants.",
        "corps_html": '<a href="http://192.168.1.1/phish">Cliquez ici</a>',
        "urls": ["http://192.168.1.1/phish"],
        "pieces_jointes": [{"name": "facture.pdf.exe", "size": 1024, "content_type": "application/octet-stream"}],
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
    }


@pytest.fixture
def sample_email_suspect():
    """Email suspect avec quelques indicateurs."""
    return {
        "message_id": "msg-003",
        "expediteur": "support@amazon-deals.top",
        "sujet": "Votre colis en attente",
        "date": "2024-01-15T14:00",
        "reply_to": "",
        "originating_ip": "",
        "corps": "Suivre ma livraison via ce lien : https://bit.ly/3xYzAbc",
        "corps_html": "",
        "urls": ["https://bit.ly/3xYzAbc"],
        "pieces_jointes": [],
        "spf": "SOFTFAIL",
        "dkim": "PASS",
        "dmarc": "NONE",
    }
