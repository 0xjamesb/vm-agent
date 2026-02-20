"""MCP tools for scanner-based exposure analysis."""

from __future__ import annotations

from integrations.assets.registry import AssetRegistry
from integrations.cve_sources.cisa_kev import CISAKEVClient
from integrations.cve_sources.epss import EPSSClient
from integrations.cve_sources.osv import OSVClient
from integrations.scanners.mock_scanner import MockScanner
from config.sla import get_sla_days, get_due_date
from models.vulnerability import Severity
from security.audit import AuditLogger
from security.validation import InputValidator, ValidationError

_validator = InputValidator()
_audit = AuditLogger.get_instance()

_CVE_PREFIXES = ["", "UBUNTU-", "DEBIAN-", "ALPINE-", "ROCKY-", "SUSE-", "RHEL-"]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


async def get_affected_assets(cve_id: str) -> list[dict]:
    """
    Find all assets in the environment that are affected by a given CVE.

    Queries the scanner for findings, then enriches each result with asset
    metadata (owner team, criticality) from the asset registry.

    Returns results sorted by asset criticality (CRITICAL first).

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-23337)
    """
    try:
        vuln_id = _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return [{"error": str(e), "cve_id": cve_id}]

    _audit.log_user_input("tool_call", "get_affected_assets", validation_passed=True, input_length=len(cve_id))

    scanner = MockScanner()
    registry = AssetRegistry()

    findings = scanner.get_findings_by_cve(vuln_id)

    if not findings:
        return []

    results = []
    seen_assets: set[str] = set()

    for scan_result in findings:
        asset_id = scan_result.asset_id
        if asset_id in seen_assets:
            continue
        seen_assets.add(asset_id)

        asset = registry.get_asset(asset_id)
        vuln = next((v for v in scan_result.vulnerabilities if v.id == vuln_id), None)

        results.append({
            "asset_id": asset_id,
            "asset_name": asset.name if asset else asset_id,
            "criticality": asset.criticality.value if asset else "UNKNOWN",
            "criticality_multiplier": asset.criticality_multiplier if asset else 1.0,
            "owner_team": asset.owner_team if asset else None,
            "owner_contact": asset.owner_contact if asset else None,
            "compliance_scope": asset.compliance_scope if asset else [],
            "package_name": vuln.affected_packages[0].name if vuln and vuln.affected_packages else None,
            "package_version": (
                vuln.affected_packages[0].affected_versions[0]
                if vuln and vuln.affected_packages and vuln.affected_packages[0].affected_versions
                else None
            ),
            "ecosystem": vuln.affected_packages[0].ecosystem if vuln and vuln.affected_packages else None,
            "scanner": scan_result.scanner_name,
            "found_at": scan_result.timestamp.isoformat(),
        })

    # Sort by criticality (CRITICAL first)
    criticality_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    results.sort(key=lambda r: criticality_rank.get(r["criticality"], 0), reverse=True)

    return results


async def get_asset_vulnerabilities(
    asset_id: str,
    min_severity: str = "MEDIUM",
) -> list[dict]:
    """
    List all open vulnerabilities found on a specific asset.

    Enriches each finding with the applicable SLA deadline based on severity
    and CISA KEV status, plus any existing ticket ID.

    Args:
        asset_id: Asset identifier (e.g. asset-auth-service)
        min_severity: Minimum severity to include: CRITICAL, HIGH, MEDIUM, or LOW
    """
    _audit.log_user_input("tool_call", "get_asset_vulnerabilities", validation_passed=True, input_length=len(asset_id))

    try:
        min_sev = Severity(min_severity.upper())
    except ValueError:
        return [{"error": f"Invalid severity '{min_severity}'. Use: CRITICAL, HIGH, MEDIUM, LOW"}]

    scanner = MockScanner()
    registry = AssetRegistry()
    kev = CISAKEVClient()
    epss = EPSSClient()

    asset = registry.get_asset(asset_id)
    if not asset:
        return [{"error": f"Asset '{asset_id}' not found"}]

    # Collect all findings for this asset
    all_scans = await scanner.list_recent_scans()
    asset_scans = [s for s in all_scans if s.asset_id == asset_id]

    # Deduplicate by CVE ID, keeping most recent
    seen: dict[str, dict] = {}
    for scan in asset_scans:
        for vuln in scan.vulnerabilities:
            if vuln.id in seen:
                continue

            sev_rank = _SEVERITY_ORDER.get(vuln.severity, 0)
            min_rank = _SEVERITY_ORDER.get(min_sev, 0)
            if sev_rank < min_rank:
                continue

            # Check KEV
            in_kev = kev.is_in_kev(vuln.id)
            kev_entry = kev.get_kev_entry(vuln.id) if in_kev else None

            # EPSS score
            epss_result = await epss.get_score(vuln.id)
            epss_score = epss_result.epss if epss_result else None

            # Priority score (basic without full OSV enrichment for speed)
            priority = 0
            if vuln.cvss_score:
                priority += int(vuln.cvss_score * 4)
            if epss_score:
                priority += int(epss_score * 30)
            if in_kev:
                priority += 30
            priority = min(priority, 100)

            sla_days = get_sla_days(vuln.severity.value, in_kev)
            due_date = get_due_date(vuln.severity.value, in_kev)

            seen[vuln.id] = {
                "cve_id": vuln.id,
                "severity": vuln.severity.value,
                "priority_score": priority,
                "in_cisa_kev": in_kev,
                "kev_due_date": kev_entry.due_date.isoformat() if kev_entry else None,
                "epss_score": epss_score,
                "package_name": vuln.affected_packages[0].name if vuln.affected_packages else None,
                "package_version": (
                    vuln.affected_packages[0].affected_versions[0]
                    if vuln.affected_packages and vuln.affected_packages[0].affected_versions
                    else None
                ),
                "sla_days": sla_days,
                "sla_due_date": due_date.isoformat(),
                "ticket_id": None,  # Populated below if ticket exists
            }

    results = sorted(seen.values(), key=lambda v: v["priority_score"], reverse=True)
    return results


async def calculate_risk_score(cve_id: str, asset_id: str) -> dict:
    """
    Calculate the contextual risk score for a CVE on a specific asset.

    Combines the vulnerability's priority score (0-100) with the asset's
    criticality multiplier to produce a business risk score (0-100).

    Also returns the applicable SLA deadline and a plain-language recommendation.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-23337)
        asset_id: Asset identifier (e.g. asset-auth-service)
    """
    try:
        vuln_id = _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e), "cve_id": cve_id}

    _audit.log_user_input("tool_call", "calculate_risk_score", validation_passed=True, input_length=len(cve_id + asset_id))

    registry = AssetRegistry()
    asset = registry.get_asset(asset_id)
    if not asset:
        return {"error": f"Asset '{asset_id}' not found"}

    osv = OSVClient()
    kev = CISAKEVClient()
    epss_client = EPSSClient()

    try:
        # Fetch vulnerability
        vuln = None
        for prefix in _CVE_PREFIXES:
            vuln = await osv.get_vulnerability(f"{prefix}{vuln_id}")
            if vuln:
                break

        if not vuln:
            return {"error": f"Vulnerability '{cve_id}' not found in OSV"}

        # Enrich
        in_kev = kev.is_in_kev(vuln_id)
        if in_kev:
            kev_entry = kev.get_kev_entry(vuln_id)
            vuln.in_cisa_kev = True
            if kev_entry:
                vuln.cisa_kev_due_date = kev_entry.due_date

        epss_result = await epss_client.get_score(vuln_id)
        if epss_result:
            vuln.epss_score = epss_result.epss
            vuln.epss_percentile = epss_result.percentile

        vuln_priority = vuln.priority_score
        multiplier = asset.criticality_multiplier
        risk_score = min(int(vuln_priority * multiplier), 100)

        sla_days = get_sla_days(vuln.severity.value, vuln.in_cisa_kev)
        due_date = get_due_date(vuln.severity.value, vuln.in_cisa_kev)

        # Plain-language recommendation
        if risk_score >= 80:
            recommendation = "Immediate remediation required. Escalate to asset owner today."
        elif risk_score >= 60:
            recommendation = "High priority. Assign ticket and track to SLA deadline."
        elif risk_score >= 40:
            recommendation = "Medium priority. Schedule remediation within SLA window."
        else:
            recommendation = "Lower priority. Track and address in next patch cycle."

        return {
            "cve_id": cve_id,
            "asset_id": asset_id,
            "asset_name": asset.name,
            "asset_criticality": asset.criticality.value,
            "criticality_multiplier": multiplier,
            "vuln_severity": vuln.severity.value,
            "vuln_priority_score": vuln_priority,
            "in_cisa_kev": vuln.in_cisa_kev,
            "epss_score": vuln.epss_score,
            "risk_score": risk_score,
            "sla_days": sla_days,
            "sla_due_date": due_date.isoformat(),
            "recommendation": recommendation,
            "compliance_scope": asset.compliance_scope,
        }

    finally:
        await osv.close()
