"""MCP tools for CVE intelligence: lookup, package checking, and priority triage."""

from __future__ import annotations

from integrations.cve_sources.cisa_kev import CISAKEVClient
from integrations.cve_sources.epss import EPSSClient
from integrations.cve_sources.osv import OSVClient
from models.vulnerability import Vulnerability
from security.audit import AuditLogger, TrustBoundary
from security.validation import InputValidator, ValidationError

# Prefixes to try when an ID doesn't match directly in OSV
_CVE_PREFIXES = ["", "UBUNTU-", "DEBIAN-", "ALPINE-", "ROCKY-", "SUSE-", "RHEL-"]

_validator = InputValidator()
_audit = AuditLogger.get_instance()


def _vuln_to_dict(vuln: Vulnerability) -> dict:
    """Convert a Vulnerability dataclass to a JSON-serializable dict."""
    return {
        "id": vuln.id,
        "aliases": vuln.aliases,
        "summary": vuln.summary,
        "details": vuln.details,
        "severity": vuln.severity.value,
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector,
        "epss_score": vuln.epss_score,
        "epss_percentile": vuln.epss_percentile,
        "exploitation_likelihood": vuln.exploitation_likelihood,
        "in_cisa_kev": vuln.in_cisa_kev,
        "cisa_kev_due_date": vuln.cisa_kev_due_date.isoformat() if vuln.cisa_kev_due_date else None,
        "is_actively_exploited": vuln.is_actively_exploited,
        "priority_score": vuln.priority_score,
        "published": vuln.published.isoformat() if vuln.published else None,
        "modified": vuln.modified.isoformat() if vuln.modified else None,
        "references": vuln.references,
        "affected_packages": [
            {
                "ecosystem": p.ecosystem,
                "name": p.name,
                "affected_versions": p.affected_versions,
                "fixed_versions": p.fixed_versions,
            }
            for p in vuln.affected_packages
        ],
    }


async def lookup_cve(cve_id: str) -> dict:
    """
    Fetch and enrich a CVE from OSV.dev, CISA KEV, and EPSS.

    Returns a dict with vulnerability details including severity, CVSS score,
    EPSS exploitation probability, CISA KEV status, affected packages, and a
    0-100 priority score (CVSS 0-40 + EPSS 0-30 + KEV 0-30).

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-3094) or OSV/GHSA ID.
    """
    try:
        vuln_id = _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e), "cve_id": cve_id}

    _audit.log_user_input("tool_call", "lookup_cve", validation_passed=True, input_length=len(cve_id))

    osv = OSVClient()
    kev = CISAKEVClient()
    epss = EPSSClient()

    try:
        vuln = None
        for prefix in _CVE_PREFIXES:
            vuln = await osv.get_vulnerability(f"{prefix}{vuln_id}")
            if vuln:
                break

        if not vuln:
            return {"error": f"No vulnerability found for {cve_id}", "cve_id": cve_id}

        # Enrich with KEV
        if kev.is_in_kev(vuln_id):
            entry = kev.get_kev_entry(vuln_id)
            vuln.in_cisa_kev = True
            if entry:
                vuln.cisa_kev_due_date = entry.due_date

        # Enrich with EPSS
        epss_score = await epss.get_score(vuln_id)
        if epss_score:
            vuln.epss_score = epss_score.epss
            vuln.epss_percentile = epss_score.percentile

        return _vuln_to_dict(vuln)

    finally:
        await osv.close()


async def check_package(ecosystem: str, package: str, version: str = "") -> list[dict]:
    """
    Query OSV.dev for vulnerabilities affecting a package, enriched with KEV and EPSS.

    Returns a list of vulnerability dicts sorted by priority_score descending.

    Args:
        ecosystem: Package ecosystem (npm, PyPI, Go, crates.io, Maven, NuGet, etc.)
        package: Package name (e.g. lodash, requests, github.com/foo/bar)
        version: Optional specific version to check (e.g. 4.17.20)
    """
    try:
        ecosystem = _validator.validate_ecosystem(ecosystem)
        package = _validator.validate_package_name(package)
        if version:
            version = _validator.validate_version(version) or ""
    except ValidationError as e:
        return [{"error": str(e)}]

    _audit.log_user_input("tool_call", "check_package", validation_passed=True, input_length=len(package))

    osv = OSVClient()
    kev = CISAKEVClient()
    epss = EPSSClient()

    try:
        vulns = await osv.query_package(ecosystem, package, version or None)

        if not vulns:
            return []

        # Collect CVE IDs for batch EPSS lookup
        cve_ids = [
            alias
            for v in vulns
            for alias in ([v.id] + v.aliases)
            if alias.startswith("CVE-")
        ]
        epss_scores = await epss.get_scores_batch(cve_ids) if cve_ids else {}

        results = []
        for vuln in vulns:
            # KEV enrichment
            for vid in [vuln.id] + vuln.aliases:
                if vid.startswith("CVE-") and kev.is_in_kev(vid):
                    vuln.in_cisa_kev = True
                    entry = kev.get_kev_entry(vid)
                    if entry:
                        vuln.cisa_kev_due_date = entry.due_date
                    break

            # EPSS enrichment
            for vid in [vuln.id] + vuln.aliases:
                if vid in epss_scores:
                    vuln.epss_score = epss_scores[vid].epss
                    vuln.epss_percentile = epss_scores[vid].percentile
                    break

            results.append(_vuln_to_dict(vuln))

        results.sort(key=lambda v: v["priority_score"], reverse=True)
        return results

    finally:
        await osv.close()


async def get_high_priority_vulns(limit: int = 20) -> list[dict]:
    """
    Get high-priority vulnerabilities: recent CISA KEV additions plus high-EPSS CVEs.

    Results are sorted by priority_score descending. Useful for daily triage.

    Args:
        limit: Maximum number of results to return (default 20, max 100).
    """
    limit = max(1, min(limit, 100))

    kev = CISAKEVClient()
    epss = EPSSClient()
    osv = OSVClient()

    try:
        results: list[dict] = []
        seen_ids: set[str] = set()

        # Recent KEV additions (last 30 days)
        recent_kev = kev.get_recent_additions(days=30)
        kev_cve_ids = [e.cve_id for e in recent_kev]

        # High EPSS scores (top 90th percentile)
        high_epss = await epss.get_high_risk(percentile_threshold=0.9, limit=limit)
        epss_cve_ids = [s.cve_id for s in high_epss]

        # Deduplicate, KEV first (higher signal)
        all_ids = list(dict.fromkeys(kev_cve_ids + epss_cve_ids))[:limit]

        for cve_id in all_ids:
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)

            vuln = None
            for prefix in _CVE_PREFIXES:
                vuln = await osv.get_vulnerability(f"{prefix}{cve_id}")
                if vuln:
                    break

            if not vuln:
                continue

            # KEV enrichment
            if kev.is_in_kev(cve_id):
                vuln.in_cisa_kev = True
                entry = kev.get_kev_entry(cve_id)
                if entry:
                    vuln.cisa_kev_due_date = entry.due_date

            # EPSS enrichment
            epss_map = await epss.get_scores_batch([cve_id])
            if cve_id in epss_map:
                vuln.epss_score = epss_map[cve_id].epss
                vuln.epss_percentile = epss_map[cve_id].percentile

            results.append(_vuln_to_dict(vuln))

        results.sort(key=lambda v: v["priority_score"], reverse=True)
        return results

    finally:
        await osv.close()


async def get_kev_recent(days: int = 7) -> list[dict]:
    """
    Get vulnerabilities recently added to the CISA Known Exploited Vulnerabilities catalog.

    These are CVEs with confirmed active exploitation in the wild. CISA mandates
    that federal agencies patch them within the listed due date.

    Args:
        days: How many days back to look (default 7, max 90).
    """
    days = max(1, min(days, 90))

    kev = CISAKEVClient()

    entries = kev.get_recent_additions(days=days)

    return [
        {
            "cve_id": e.cve_id,
            "vendor_project": e.vendor_project,
            "product": e.product,
            "vulnerability_name": e.vulnerability_name,
            "date_added": e.date_added.isoformat(),
            "due_date": e.due_date.isoformat(),
            "known_ransomware_use": e.known_ransomware_use,
            "short_description": e.short_description,
            "required_action": e.required_action,
        }
        for e in entries
    ]
