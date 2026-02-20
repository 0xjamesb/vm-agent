"""
Mock scanner for development and testing.

This allows manual input of vulnerabilities via CSV or direct input,
simulating what a real scanner integration would provide.
"""

import csv
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from models import Vulnerability, AffectedPackage, Severity
from .base import Scanner, ScanResult


# Realistic seed findings linking sample CVEs to the seeded asset registry.
# These reflect real-world vulnerability patterns for common packages.
_SEED_FINDINGS: list[dict] = [
    # Auth Service: lodash prototype pollution (well-known)
    {"asset_id": "asset-auth-service",    "cve_id": "CVE-2021-23337", "ecosystem": "npm",   "package": "lodash",       "version": "4.17.20", "severity": "HIGH"},
    {"asset_id": "asset-auth-service",    "cve_id": "CVE-2020-28500", "ecosystem": "npm",   "package": "lodash",       "version": "4.17.20", "severity": "MEDIUM"},
    # Auth Service: jsonwebtoken
    {"asset_id": "asset-auth-service",    "cve_id": "CVE-2022-23529", "ecosystem": "npm",   "package": "jsonwebtoken", "version": "8.5.1",   "severity": "HIGH"},
    # Payment API: requests (Python)
    {"asset_id": "asset-payment-api",     "cve_id": "CVE-2023-32681", "ecosystem": "PyPI",  "package": "requests",     "version": "2.28.0",  "severity": "MEDIUM"},
    # Payment API: cryptography
    {"asset_id": "asset-payment-api",     "cve_id": "CVE-2023-49083", "ecosystem": "PyPI",  "package": "cryptography", "version": "38.0.0",  "severity": "HIGH"},
    # Customer Portal: axios SSRF
    {"asset_id": "asset-customer-portal", "cve_id": "CVE-2023-45857", "ecosystem": "npm",   "package": "axios",        "version": "0.27.0",  "severity": "MEDIUM"},
    # Data Pipeline: numpy
    {"asset_id": "asset-data-pipeline",   "cve_id": "CVE-2021-34141", "ecosystem": "PyPI",  "package": "numpy",        "version": "1.23.0",  "severity": "MEDIUM"},
    # Internal Tools: express
    {"asset_id": "asset-internal-tools",  "cve_id": "CVE-2022-24999", "ecosystem": "npm",   "package": "express",      "version": "4.18.0",  "severity": "HIGH"},
]


class MockScanner(Scanner):
    """
    Mock scanner that reads from CSV files or accepts direct input.

    Seeded with realistic findings across the sample asset registry so the
    system is immediately usable without external scanner credentials.

    CSV format:
    asset_id,cve_id,package_ecosystem,package_name,package_version,severity
    """

    def __init__(self, data_dir: Optional[Path] = None, seed: bool = True):
        self.data_dir = data_dir or Path("./data/scans")
        self._results: dict[str, ScanResult] = {}

        if seed:
            self._seed()

    def _seed(self):
        """Populate with realistic findings across the sample asset registry."""
        for finding in _SEED_FINDINGS:
            vuln = Vulnerability(
                id=finding["cve_id"],
                summary=f"Vulnerability in {finding['package']} {finding['version']}",
                severity=Severity(finding["severity"]),
                affected_packages=[
                    AffectedPackage(
                        ecosystem=finding["ecosystem"],
                        name=finding["package"],
                        affected_versions=[finding["version"]],
                    )
                ],
            )
            result = ScanResult(
                scan_id=str(uuid.uuid4()),
                asset_id=finding["asset_id"],
                timestamp=datetime.now(),
                vulnerabilities=[vuln],
                scanner_name="MockScanner (Seeded)",
            )
            self._results[result.scan_id] = result

    def get_findings_by_cve(self, cve_id: str) -> list[ScanResult]:
        """Return all scan results that contain a specific CVE ID."""
        matches = []
        for result in self._results.values():
            if any(v.id == cve_id for v in result.vulnerabilities):
                matches.append(result)
        return matches

    async def import_from_csv(self, csv_path: Path, asset_id: str) -> ScanResult:
        """Import scan results from a CSV file."""
        vulnerabilities = []

        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vuln = Vulnerability(
                    id=row.get("cve_id", ""),
                    summary=row.get("summary", f"Vulnerability in {row.get('package_name', 'unknown')}"),
                    severity=Severity(row.get("severity", "UNKNOWN").upper()),
                    affected_packages=[
                        AffectedPackage(
                            ecosystem=row.get("package_ecosystem", ""),
                            name=row.get("package_name", ""),
                            affected_versions=[row.get("package_version", "")],
                        )
                    ],
                )
                vulnerabilities.append(vuln)

        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            asset_id=asset_id,
            timestamp=datetime.now(),
            vulnerabilities=vulnerabilities,
            scanner_name="MockScanner (CSV Import)",
        )

        self._results[result.scan_id] = result
        return result

    async def add_vulnerability(
        self,
        asset_id: str,
        cve_id: str,
        package_ecosystem: str,
        package_name: str,
        package_version: str,
        severity: str = "UNKNOWN",
    ) -> ScanResult:
        """Manually add a vulnerability finding."""
        vuln = Vulnerability(
            id=cve_id,
            summary=f"Vulnerability in {package_name}",
            severity=Severity(severity.upper()),
            affected_packages=[
                AffectedPackage(
                    ecosystem=package_ecosystem,
                    name=package_name,
                    affected_versions=[package_version],
                )
            ],
        )

        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            asset_id=asset_id,
            timestamp=datetime.now(),
            vulnerabilities=[vuln],
            scanner_name="MockScanner (Manual)",
        )

        self._results[result.scan_id] = result
        return result

    async def scan_asset(self, asset_id: str) -> ScanResult:
        """No-op scan - returns empty results. Use import_from_csv or add_vulnerability."""
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            asset_id=asset_id,
            timestamp=datetime.now(),
            vulnerabilities=[],
            scanner_name="MockScanner",
        )

    async def get_scan_results(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a stored scan result."""
        return self._results.get(scan_id)

    async def list_recent_scans(self, limit: int = 100) -> list[ScanResult]:
        """List stored scan results."""
        results = sorted(
            self._results.values(),
            key=lambda r: r.timestamp,
            reverse=True,
        )
        return results[:limit]
