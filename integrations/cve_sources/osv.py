"""
OSV.dev API Client

Security controls:
- Input validation on all parameters
- Audit logging for all network calls
- Sanitization of all external data
- Prompt injection pattern detection
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Optional

import httpx

from models import Vulnerability, AffectedPackage, Severity
from security import (
    InputValidator,
    ValidationError,
    Sanitizer,
    AuditLogger,
    TrustBoundary,
)
from .base import VulnerabilitySource


class OSVClient(VulnerabilitySource):
    """
    Client for the OSV.dev API.

    OSV (Open Source Vulnerabilities) is a distributed vulnerability database
    for open source projects. It aggregates data from multiple sources including
    GitHub Security Advisories, PyPI, npm, Go, and more.

    API Documentation: https://osv.dev/docs/

    Security: All responses are sanitized before use. All calls are audit logged.
    """

    BASE_URL = "https://api.osv.dev/v1"

    # Supported ecosystems in OSV
    ECOSYSTEMS = [
        "npm", "PyPI", "Go", "crates.io", "Maven", "NuGet",
        "Packagist", "RubyGems", "Hex", "Pub", "SwiftURL",
        "Linux", "Debian", "Alpine", "Ubuntu", "Rocky Linux",
    ]

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._audit = AuditLogger.get_instance()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    def _parse_severity(self, osv_data: dict) -> tuple[Severity, Optional[float], Optional[str]]:
        """Extract severity info from OSV response."""
        severity = Severity.UNKNOWN
        cvss_score = None
        cvss_vector = None

        # Check severity array
        severities = osv_data.get("severity", [])
        for sev in severities:
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score")
                break

        # Check database_specific for CVSS score
        db_specific = osv_data.get("database_specific", {})
        if "cvss" in db_specific:
            cvss_score = db_specific["cvss"].get("score")
        elif "severity" in db_specific:
            sev_str = str(db_specific["severity"]).upper()
            if sev_str in [s.value for s in Severity]:
                severity = Severity(sev_str)

        # Derive severity from CVSS score if available
        if cvss_score:
            # Validate CVSS score is in valid range
            try:
                cvss_score = float(cvss_score)
                if not 0.0 <= cvss_score <= 10.0:
                    cvss_score = None
                else:
                    severity = Severity.from_cvss(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        return severity, cvss_score, cvss_vector

    def _parse_affected(self, osv_data: dict) -> list[AffectedPackage]:
        """Extract affected packages from OSV response."""
        affected_packages = []

        for affected in osv_data.get("affected", []):
            pkg = affected.get("package", {})
            ecosystem = str(pkg.get("ecosystem", ""))
            name = str(pkg.get("name", ""))

            if not name:
                continue

            # Sanitize package name from external source
            name = str(Sanitizer.sanitize_text(name, max_length=214))
            ecosystem = str(Sanitizer.sanitize_text(ecosystem, max_length=50))

            # Extract affected version ranges
            affected_versions = []
            fixed_versions = []

            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if "introduced" in event:
                        version = str(Sanitizer.sanitize_text(
                            str(event["introduced"]), max_length=128
                        ))
                        affected_versions.append(f">={version}")
                    if "fixed" in event:
                        version = str(Sanitizer.sanitize_text(
                            str(event["fixed"]), max_length=128
                        ))
                        fixed_versions.append(version)

            # Also check explicit versions list
            explicit_versions = affected.get("versions", [])
            for v in explicit_versions[:100]:  # Limit to prevent DoS
                version = str(Sanitizer.sanitize_text(str(v), max_length=128))
                affected_versions.append(version)

            affected_packages.append(
                AffectedPackage(
                    ecosystem=ecosystem,
                    name=name,
                    affected_versions=affected_versions,
                    fixed_versions=fixed_versions,
                )
            )

        return affected_packages

    def _parse_vulnerability(self, osv_data: dict) -> Vulnerability:
        """
        Convert OSV API response to our Vulnerability model.

        All text fields are sanitized and checked for injection patterns.
        """
        severity, cvss_score, cvss_vector = self._parse_severity(osv_data)
        affected_packages = self._parse_affected(osv_data)

        # Sanitize text fields from external source
        vuln_id = str(Sanitizer.sanitize_text(
            str(osv_data.get("id", "")), max_length=50
        ))
        summary = Sanitizer.sanitize_text(
            str(osv_data.get("summary", "")), max_length=500
        )
        details = Sanitizer.sanitize_text(
            str(osv_data.get("details", "")), max_length=5000
        )

        # Check for prompt injection patterns in text fields
        suspicious_patterns = []
        for text in [str(summary), str(details)]:
            patterns = Sanitizer.check_for_injection_patterns(text)
            suspicious_patterns.extend(patterns)

        if suspicious_patterns:
            self._audit.log_external_data_parse(
                source="OSV.dev",
                data_type="vulnerability",
                record_count=1,
                sanitization_applied=True,
                suspicious_patterns=suspicious_patterns,
            )

        # Parse dates
        published = None
        modified = None
        if osv_data.get("published"):
            try:
                published = datetime.fromisoformat(
                    osv_data["published"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        if osv_data.get("modified"):
            try:
                modified = datetime.fromisoformat(
                    osv_data["modified"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        # Extract and sanitize references (URLs)
        references = []
        for ref in osv_data.get("references", [])[:50]:  # Limit count
            url = Sanitizer.sanitize_url(ref.get("url"))
            if url:
                references.append(url)

        # Extract aliases (other IDs like CVE)
        aliases = []
        for alias in osv_data.get("aliases", [])[:20]:  # Limit count
            sanitized = str(Sanitizer.sanitize_text(str(alias), max_length=50))
            if sanitized:
                aliases.append(sanitized)

        return Vulnerability(
            id=vuln_id,
            summary=str(summary),
            details=str(details),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            published=published,
            modified=modified,
            references=references,
            aliases=aliases,
        )

    async def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """
        Fetch a specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (CVE-XXXX-XXXXX, GHSA-XXXX, OSV-XXXX, etc.)

        Returns:
            Vulnerability object or None if not found.

        Raises:
            ValidationError: If vuln_id format is invalid
        """
        # Validate input
        vuln_id = InputValidator.validate_vuln_id(vuln_id)

        client = await self._get_client()
        url = f"/vulns/{vuln_id}"
        start_time = time.time()

        try:
            response = await client.get(url)
            duration_ms = (time.time() - start_time) * 1000

            # Audit log the network call
            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="GET",
                success=response.status_code == 200,
                response_size=len(response.content),
                duration_ms=duration_ms,
            )

            if response.status_code == 404:
                return None

            response.raise_for_status()
            data = response.json()

            # Log external data parsing
            self._audit.log_external_data_parse(
                source="OSV.dev",
                data_type="vulnerability",
                record_count=1,
                sanitization_applied=True,
            )

            return self._parse_vulnerability(data)

        except httpx.HTTPStatusError as e:
            duration_ms = (time.time() - start_time) * 1000
            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="GET",
                success=False,
                error=str(e),
                duration_ms=duration_ms,
            )
            if e.response.status_code == 404:
                return None
            raise

    async def query_package(
        self,
        ecosystem: str,
        package_name: str,
        version: Optional[str] = None,
    ) -> list[Vulnerability]:
        """
        Query vulnerabilities affecting a specific package.

        Args:
            ecosystem: Package ecosystem (npm, PyPI, Go, etc.)
            package_name: Name of the package
            version: Optional specific version to check

        Returns:
            List of vulnerabilities affecting this package.

        Raises:
            ValidationError: If any parameter format is invalid
        """
        # Validate all inputs
        ecosystem = InputValidator.validate_ecosystem(ecosystem)
        package_name = InputValidator.validate_package_name(package_name)
        version = InputValidator.validate_version(version)

        client = await self._get_client()
        url = "/query"
        start_time = time.time()

        payload: dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }

        if version:
            payload["version"] = version

        try:
            response = await client.post(url, json=payload)
            duration_ms = (time.time() - start_time) * 1000

            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="POST",
                success=response.status_code == 200,
                response_size=len(response.content),
                duration_ms=duration_ms,
            )

            response.raise_for_status()
            data = response.json()

            vulns_data = data.get("vulns", [])

            # Log external data parsing
            self._audit.log_external_data_parse(
                source="OSV.dev",
                data_type="vulnerability_list",
                record_count=len(vulns_data),
                sanitization_applied=True,
            )

            vulnerabilities = []
            for vuln_data in vulns_data:
                vulnerabilities.append(self._parse_vulnerability(vuln_data))

            return vulnerabilities

        except httpx.HTTPStatusError as e:
            duration_ms = (time.time() - start_time) * 1000
            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="POST",
                success=False,
                error=str(e),
                duration_ms=duration_ms,
            )
            raise

    async def batch_query(
        self,
        queries: list[dict[str, Any]],
    ) -> list[list[Vulnerability]]:
        """
        Batch query multiple packages at once.

        Args:
            queries: List of query dicts, each with 'package' and optional 'version'

        Returns:
            List of vulnerability lists, one per query.
        """
        # Validate all queries
        validated_queries = []
        for query in queries[:100]:  # Limit batch size
            pkg = query.get("package", {})
            ecosystem = InputValidator.validate_ecosystem(pkg.get("ecosystem", ""))
            package_name = InputValidator.validate_package_name(pkg.get("name", ""))
            version = InputValidator.validate_version(query.get("version"))

            validated_query: dict[str, Any] = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                }
            }
            if version:
                validated_query["version"] = version
            validated_queries.append(validated_query)

        client = await self._get_client()
        url = "/querybatch"
        start_time = time.time()

        payload = {"queries": validated_queries}

        try:
            response = await client.post(url, json=payload)
            duration_ms = (time.time() - start_time) * 1000

            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="POST",
                success=response.status_code == 200,
                response_size=len(response.content),
                duration_ms=duration_ms,
            )

            response.raise_for_status()
            data = response.json()

            results = []
            total_vulns = 0
            for result in data.get("results", []):
                vulns = [
                    self._parse_vulnerability(v) for v in result.get("vulns", [])
                ]
                total_vulns += len(vulns)
                results.append(vulns)

            self._audit.log_external_data_parse(
                source="OSV.dev",
                data_type="vulnerability_batch",
                record_count=total_vulns,
                sanitization_applied=True,
            )

            return results

        except httpx.HTTPStatusError as e:
            duration_ms = (time.time() - start_time) * 1000
            self._audit.log_network_call(
                boundary=TrustBoundary.NETWORK_OSV,
                url=f"{self.BASE_URL}{url}",
                method="POST",
                success=False,
                error=str(e),
                duration_ms=duration_ms,
            )
            raise

    async def get_recent(self, limit: int = 100) -> list[Vulnerability]:
        """
        Get recently modified vulnerabilities.

        Note: OSV doesn't have a direct "recent" endpoint, so this queries
        multiple ecosystems and sorts by modified date.
        """
        # Validate limit
        limit = max(1, min(limit, 1000))

        # For MVP, we'll fetch from a few key ecosystems
        common_packages = [
            ("npm", "lodash"),
            ("npm", "axios"),
            ("PyPI", "requests"),
            ("PyPI", "django"),
            ("Go", "golang.org/x/crypto"),
        ]

        tasks = [
            self.query_package(ecosystem, package)
            for ecosystem, package in common_packages
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_vulns: list[Vulnerability] = []
        for result in results:
            if isinstance(result, list):
                all_vulns.extend(result)

        # Deduplicate by ID and sort by modified date
        seen = set()
        unique_vulns = []
        for vuln in all_vulns:
            if vuln.id not in seen:
                seen.add(vuln.id)
                unique_vulns.append(vuln)

        unique_vulns.sort(key=lambda v: v.modified or datetime.min, reverse=True)
        return unique_vulns[:limit]
