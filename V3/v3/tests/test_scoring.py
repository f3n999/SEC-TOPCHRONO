"""Tests du module de scoring."""
import pytest
from src.scoring.risk_scorer import score_email, compute_raw_score, determine_risk_level


class TestScoring:

    def test_empty_anomalies(self):
        result = score_email([])
        assert result["score"] == 0
        assert result["niveau"] == "LOW"

    def test_low_score(self):
        anomalies = [{"score": 5, "severite": "faible", "description": "test", "rule": "test"}]
        result = score_email(anomalies)
        assert result["score"] == 5
        assert result["niveau"] == "LOW"

    def test_medium_score(self):
        anomalies = [
            {"score": 20, "severite": "moyenne", "description": "test1", "rule": "r1"},
            {"score": 20, "severite": "moyenne", "description": "test2", "rule": "r2"},
        ]
        result = score_email(anomalies)
        assert result["score"] == 40
        assert result["niveau"] == "MEDIUM"

    def test_high_score(self):
        anomalies = [
            {"score": 40, "severite": "haute", "description": "test1", "rule": "r1"},
            {"score": 40, "severite": "haute", "description": "test2", "rule": "r2"},
        ]
        result = score_email(anomalies)
        assert result["score"] == 80
        assert result["niveau"] == "HIGH"

    def test_score_capped_at_100(self):
        anomalies = [{"score": 40, "severite": "haute", "description": f"test{i}", "rule": f"r{i}"} for i in range(5)]
        result = score_email(anomalies)
        assert result["score"] == 100

    def test_determine_risk_levels(self):
        assert determine_risk_level(0) == "LOW"
        assert determine_risk_level(30) == "LOW"
        assert determine_risk_level(31) == "MEDIUM"
        assert determine_risk_level(60) == "MEDIUM"
        assert determine_risk_level(61) == "HIGH"
        assert determine_risk_level(100) == "HIGH"
