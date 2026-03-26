"""Tests du moteur de detection."""
import pytest
from src.detection.engine import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine("config/rules.yaml")


class TestDetectionEngine:
    """Tests du moteur de detection principal."""

    def test_clean_email_no_anomalies(self, engine, sample_email_clean):
        """Un email clean de microsoft.com doit etre whiteliste."""
        anomalies = engine.analyser(sample_email_clean)
        assert len(anomalies) == 0

    def test_phishing_email_multiple_anomalies(self, engine, sample_email_phishing):
        """Un email phishing doit declencher plusieurs regles."""
        anomalies = engine.analyser(sample_email_phishing)
        assert len(anomalies) > 3
        rules = [a["rule"] for a in anomalies]
        assert "spf_fail" in rules
        assert "dkim_fail" in rules
        assert "dmarc_fail" in rules
        assert "reply_to_mismatch" in rules

    def test_suspect_email_some_anomalies(self, engine, sample_email_suspect):
        """Un email suspect doit avoir quelques anomalies."""
        anomalies = engine.analyser(sample_email_suspect)
        assert len(anomalies) >= 1
        rules = [a["rule"] for a in anomalies]
        assert "suspicious_tld" in rules

    def test_whitelist_skips_analysis(self, engine):
        """Les domaines whitelistes ne doivent pas etre analyses."""
        email = {
            "expediteur": "user@microsoft.com",
            "sujet": "urgent cliquez ici mot de passe",
            "corps": "test",
            "corps_html": "",
            "reply_to": "",
            "urls": [],
            "pieces_jointes": [],
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
        }
        anomalies = engine.analyser(email)
        assert len(anomalies) == 0


class TestAuthHeaders:
    """Tests des regles d'authentification."""

    def test_spf_fail(self, engine):
        email = {
            "expediteur": "test@unknown.net",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [], "pieces_jointes": [],
            "spf": "FAIL", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        rules = [a["rule"] for a in anomalies]
        assert "spf_fail" in rules

    def test_all_pass_no_auth_anomalies(self, engine):
        email = {
            "expediteur": "test@unknown.net",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [], "pieces_jointes": [],
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        auth_rules = [a for a in anomalies if a["rule"].startswith(("spf_", "dkim_", "dmarc_"))]
        assert len(auth_rules) == 0


class TestHomoglyphs:
    """Tests de la detection d'homoglyphes."""

    def test_paypal_homoglyph(self, engine):
        email = {
            "expediteur": "info@paypa1.com",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [], "pieces_jointes": [],
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        rules = [a["rule"] for a in anomalies]
        assert "homoglyph" in rules

    def test_google_homoglyph(self, engine):
        email = {
            "expediteur": "alert@g00gle.com",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [], "pieces_jointes": [],
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        rules = [a["rule"] for a in anomalies]
        assert "homoglyph" in rules


class TestAttachments:
    """Tests des pieces jointes."""

    def test_exe_attachment(self, engine):
        email = {
            "expediteur": "test@unknown.net",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [],
            "pieces_jointes": [{"name": "document.exe"}],
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        rules = [a["rule"] for a in anomalies]
        assert "dangerous_attachment" in rules

    def test_double_extension(self, engine):
        email = {
            "expediteur": "test@unknown.net",
            "sujet": "", "corps": "", "corps_html": "",
            "reply_to": "", "urls": [],
            "pieces_jointes": [{"name": "facture.pdf.exe"}],
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
        }
        anomalies = engine.analyser(email)
        rules = [a["rule"] for a in anomalies]
        assert "double_extension" in rules
