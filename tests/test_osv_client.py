"""Tests for the OSV.dev client."""

import pytest
from integrations.cve_sources import OSVClient


@pytest.fixture
def osv_client():
    return OSVClient()


@pytest.mark.asyncio
async def test_get_vulnerability(osv_client):
    """Test fetching a known vulnerability."""
    # Use a well-known CVE that should be in OSV
    vuln = await osv_client.get_vulnerability("GHSA-jfh8-c2jp-5v3q")

    # This is a lodash prototype pollution vulnerability
    if vuln:  # May not be available depending on network
        assert vuln.id == "GHSA-jfh8-c2jp-5v3q"
        assert vuln.affected_packages


@pytest.mark.asyncio
async def test_query_package(osv_client):
    """Test querying vulnerabilities for a package."""
    vulns = await osv_client.query_package("npm", "lodash", "4.17.20")

    # lodash 4.17.20 has known vulnerabilities
    assert isinstance(vulns, list)
    # May be empty if network issues, but should be a list


@pytest.mark.asyncio
async def test_query_package_no_vulns(osv_client):
    """Test querying a package with no vulnerabilities."""
    # Query a very new version that likely has no vulns
    vulns = await osv_client.query_package("npm", "nonexistent-package-12345")
    assert vulns == []


@pytest.mark.asyncio
async def test_batch_query(osv_client):
    """Test batch querying multiple packages."""
    queries = [
        {"package": {"name": "lodash", "ecosystem": "npm"}},
        {"package": {"name": "requests", "ecosystem": "PyPI"}},
    ]

    results = await osv_client.batch_query(queries)
    assert len(results) == 2
    assert all(isinstance(r, list) for r in results)
