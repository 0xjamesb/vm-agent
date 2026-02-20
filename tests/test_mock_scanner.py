"""Tests for the enhanced mock scanner."""

import pytest

from integrations.scanners.mock_scanner import MockScanner


@pytest.fixture
def scanner():
    return MockScanner(seed=True)


@pytest.fixture
def empty_scanner():
    return MockScanner(seed=False)


class TestMockScanner:
    def test_seeds_findings_on_init(self, scanner):
        scans = scanner._results
        assert len(scans) > 0

    def test_empty_scanner_has_no_findings(self, empty_scanner):
        assert len(empty_scanner._results) == 0

    def test_get_findings_by_cve_known(self, scanner):
        # lodash CVE is seeded on asset-auth-service
        results = scanner.get_findings_by_cve("CVE-2021-23337")
        assert len(results) >= 1
        asset_ids = [r.asset_id for r in results]
        assert "asset-auth-service" in asset_ids

    def test_get_findings_by_cve_unknown(self, scanner):
        results = scanner.get_findings_by_cve("CVE-9999-99999")
        assert results == []

    @pytest.mark.asyncio
    async def test_list_recent_scans(self, scanner):
        scans = await scanner.list_recent_scans()
        assert len(scans) > 0

    @pytest.mark.asyncio
    async def test_list_recent_scans_limit(self, scanner):
        scans = await scanner.list_recent_scans(limit=3)
        assert len(scans) <= 3

    @pytest.mark.asyncio
    async def test_add_vulnerability(self, empty_scanner):
        result = await empty_scanner.add_vulnerability(
            asset_id="asset-test",
            cve_id="CVE-2024-1234",
            package_ecosystem="npm",
            package_name="some-package",
            package_version="1.0.0",
            severity="HIGH",
        )
        assert result.asset_id == "asset-test"
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].id == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_get_scan_results(self, empty_scanner):
        result = await empty_scanner.add_vulnerability(
            "asset-test", "CVE-2024-1234", "npm", "pkg", "1.0.0"
        )
        fetched = await empty_scanner.get_scan_results(result.scan_id)
        assert fetched is not None
        assert fetched.scan_id == result.scan_id

    @pytest.mark.asyncio
    async def test_get_scan_results_missing(self, scanner):
        result = await scanner.get_scan_results("nonexistent-scan-id")
        assert result is None
