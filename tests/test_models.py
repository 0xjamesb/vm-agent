"""Tests for data models."""

import pytest
from models import Vulnerability, Severity, AffectedPackage, Asset, AssetCriticality


class TestVulnerability:
    def test_severity_from_cvss(self):
        assert Severity.from_cvss(9.5) == Severity.CRITICAL
        assert Severity.from_cvss(8.0) == Severity.HIGH
        assert Severity.from_cvss(5.0) == Severity.MEDIUM
        assert Severity.from_cvss(2.0) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.UNKNOWN

    def test_priority_score_with_cvss(self):
        vuln = Vulnerability(
            id="CVE-2024-1234",
            summary="Test vulnerability",
            cvss_score=9.0,  # Should contribute 36 points
        )
        assert vuln.priority_score == 36

    def test_priority_score_with_kev(self):
        vuln = Vulnerability(
            id="CVE-2024-1234",
            summary="Test vulnerability",
            in_cisa_kev=True,  # Should contribute 30 points
        )
        assert vuln.priority_score == 30

    def test_priority_score_with_epss(self):
        vuln = Vulnerability(
            id="CVE-2024-1234",
            summary="Test vulnerability",
            epss_score=0.5,  # Should contribute 15 points
        )
        assert vuln.priority_score == 15

    def test_priority_score_combined(self):
        vuln = Vulnerability(
            id="CVE-2024-1234",
            summary="Test vulnerability",
            cvss_score=10.0,  # 40 points
            in_cisa_kev=True,  # 30 points
            epss_score=1.0,  # 30 points
        )
        # Max is 100
        assert vuln.priority_score == 100

    def test_exploitation_likelihood(self):
        vuln = Vulnerability(id="test", summary="test")

        vuln.epss_score = None
        assert vuln.exploitation_likelihood == "Unknown"

        vuln.epss_score = 0.6
        assert vuln.exploitation_likelihood == "Very High"

        vuln.epss_score = 0.25
        assert vuln.exploitation_likelihood == "High"

        vuln.epss_score = 0.08
        assert vuln.exploitation_likelihood == "Moderate"

        vuln.epss_score = 0.02
        assert vuln.exploitation_likelihood == "Low"

    def test_is_actively_exploited(self):
        vuln = Vulnerability(id="test", summary="test")
        assert vuln.is_actively_exploited is False

        vuln.in_cisa_kev = True
        assert vuln.is_actively_exploited is True


class TestAsset:
    def test_criticality_multiplier(self):
        asset = Asset(id="test", name="Test")

        asset.criticality = AssetCriticality.CRITICAL
        assert asset.criticality_multiplier == 2.0

        asset.criticality = AssetCriticality.HIGH
        assert asset.criticality_multiplier == 1.5

        asset.criticality = AssetCriticality.MEDIUM
        assert asset.criticality_multiplier == 1.0

        asset.criticality = AssetCriticality.LOW
        assert asset.criticality_multiplier == 0.5
