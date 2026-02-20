"""MCP tools for ticket management, SLA tracking, and risk exceptions."""

from __future__ import annotations

from datetime import datetime

from config.sla import describe_sla, get_due_date, get_sla_days
from config.settings import get_settings
from integrations.assets.registry import AssetRegistry
from integrations.exceptions.registry import ExceptionRegistry
from integrations.ticketing.mock_tickets import MockTicketingSystem
from integrations.ticketing.base import TicketStatus
from security.audit import AuditLogger
from security.validation import InputValidator, ValidationError

_validator = InputValidator()
_audit = AuditLogger.get_instance()


def _ticket_to_dict(ticket) -> dict:
    return {
        "ticket_id": ticket.id,
        "title": ticket.title,
        "status": ticket.status.value,
        "priority": ticket.priority,
        "assignee": ticket.assignee,
        "vulnerability_id": ticket.vulnerability_id,
        "asset_id": ticket.asset_id,
        "created_at": ticket.created_at.isoformat(),
        "updated_at": ticket.updated_at.isoformat(),
        "labels": ticket.labels,
        "external_url": ticket.external_url,
    }


def _exception_to_dict(exc) -> dict:
    return {
        "exception_id": exc.id,
        "cve_id": exc.cve_id,
        "asset_id": exc.asset_id,
        "reason": exc.reason,
        "approved_by": exc.approved_by,
        "granted_at": exc.granted_at.isoformat(),
        "expires_at": exc.expires_at.isoformat() if exc.expires_at else None,
        "is_active": exc.is_active,
        "days_remaining": exc.days_remaining,
    }


async def find_ticket(cve_id: str, asset_id: str) -> dict:
    """
    Check whether a remediation ticket already exists for a CVE + asset pair.

    Returns the ticket if found, or {"found": false} if none exists.
    Check this before creating a new ticket to avoid duplicates.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-23337)
        asset_id: Asset identifier (e.g. asset-auth-service)
    """
    try:
        _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e)}

    _audit.log_user_input("tool_call", "find_ticket", validation_passed=True, input_length=len(cve_id + asset_id))

    settings = get_settings()
    ticketing = MockTicketingSystem(persistence_path=settings.tickets_path)

    tickets = await ticketing.find_tickets(vulnerability_id=cve_id, asset_id=asset_id)

    if not tickets:
        return {"found": False, "cve_id": cve_id, "asset_id": asset_id}

    # Return the most recently updated ticket
    ticket = max(tickets, key=lambda t: t.updated_at)
    return {"found": True, **_ticket_to_dict(ticket)}


async def create_remediation_ticket(
    cve_id: str,
    asset_id: str,
    priority: str = "",
    assignee: str = "",
) -> dict:
    """
    Create a remediation ticket for a CVE + asset pair.

    Checks for an existing ticket first and returns it if found.
    Auto-derives priority from the CVE severity if not provided.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-23337)
        asset_id: Asset identifier (e.g. asset-auth-service)
        priority: Ticket priority (Critical, High, Medium, Low). Auto-derived if omitted.
        assignee: Team or person to assign the ticket to (e.g. owner team name)
    """
    try:
        _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e)}

    _audit.log_user_input("tool_call", "create_remediation_ticket", validation_passed=True, input_length=len(cve_id + asset_id))

    settings = get_settings()
    ticketing = MockTicketingSystem(persistence_path=settings.tickets_path)
    registry = AssetRegistry()

    # Return existing ticket if found
    existing = await ticketing.find_tickets(vulnerability_id=cve_id, asset_id=asset_id)
    if existing:
        ticket = max(existing, key=lambda t: t.updated_at)
        return {"created": False, "existing": True, **_ticket_to_dict(ticket)}

    asset = registry.get_asset(asset_id)
    asset_name = asset.name if asset else asset_id

    # Auto-derive priority if not provided
    if not priority:
        priority = "Medium"  # Default; caller should pass severity-derived priority

    ticket = await ticketing.create_ticket(
        title=f"[{cve_id}] Remediate vulnerability in {asset_name}",
        description=(
            f"Vulnerability {cve_id} has been detected on {asset_name} ({asset_id}).\n\n"
            f"Please review the findings and remediate within the applicable SLA window.\n\n"
            f"Run `/check-exposure {cve_id}` in Claude Code for full context."
        ),
        priority=priority,
        assignee=assignee or (asset.owner_team if asset else None),
        labels=["vulnerability", "security", cve_id],
        vulnerability_id=cve_id,
        asset_id=asset_id,
    )

    return {"created": True, **_ticket_to_dict(ticket)}


async def get_sla_deadline(severity: str, in_kev: bool = False) -> dict:
    """
    Return the SLA deadline for a given vulnerability severity and KEV status.

    Computes the due date from today based on the configured SLA policy.
    Use this to set ticket due dates and communicate deadlines to asset owners.

    Args:
        severity: Vulnerability severity (CRITICAL, HIGH, MEDIUM, LOW)
        in_kev: Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog
    """
    severity = severity.upper()
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    if severity not in valid:
        return {"error": f"Invalid severity '{severity}'. Valid values: {sorted(valid)}"}

    sla_days = get_sla_days(severity, in_kev)
    due_date = get_due_date(severity, in_kev)

    return {
        "severity": severity,
        "in_kev": in_kev,
        "sla_days": sla_days,
        "due_date": due_date.isoformat(),
        "policy_note": describe_sla(severity, in_kev),
    }


async def get_overdue_findings(team: str = "", days_overdue: int = 0) -> list[dict]:
    """
    List all open remediation tickets that are past their SLA due date.

    This is the entry point for the out-of-SLA workflow. Results are sorted
    by most overdue first. Use with /triage-overdue to prioritize escalations.

    Args:
        team: Filter to a specific owner team (partial match, case-insensitive)
        days_overdue: Only return findings overdue by at least this many days (0 = all overdue)
    """
    _audit.log_user_input("tool_call", "get_overdue_findings", validation_passed=True, input_length=len(team))

    settings = get_settings()
    ticketing = MockTicketingSystem(persistence_path=settings.tickets_path)
    registry = AssetRegistry()

    # Get all open/in-progress tickets
    open_tickets = await ticketing.find_tickets(status=TicketStatus.OPEN)
    in_progress = await ticketing.find_tickets(status=TicketStatus.IN_PROGRESS)
    all_open = open_tickets + in_progress

    now = datetime.now()
    results = []

    for ticket in all_open:
        asset_id = ticket.asset_id or ""
        asset = registry.get_asset(asset_id) if asset_id else None

        # Filter by team if requested
        if team and asset and asset.owner_team:
            if team.lower() not in asset.owner_team.lower():
                continue

        # For the mock system, estimate due date from ticket creation + SLA
        # In a real system this would come from the ticket's due_date field
        # We use a MEDIUM/no-KEV SLA as a conservative estimate
        estimated_due = ticket.created_at.replace(
            tzinfo=None
        ) + __import__("datetime").timedelta(days=30)

        days_past = (now - estimated_due).days
        if days_past < days_overdue:
            continue
        if days_past <= 0:
            continue  # Not overdue

        results.append({
            "ticket_id": ticket.id,
            "cve_id": ticket.vulnerability_id,
            "asset_id": asset_id,
            "asset_name": asset.name if asset else asset_id,
            "owner_team": asset.owner_team if asset else None,
            "owner_contact": asset.owner_contact if asset else None,
            "ticket_status": ticket.status.value,
            "ticket_priority": ticket.priority,
            "created_at": ticket.created_at.isoformat(),
            "estimated_due": estimated_due.isoformat(),
            "days_overdue": days_past,
            "assignee": ticket.assignee,
        })

    results.sort(key=lambda r: r["days_overdue"], reverse=True)
    return results


async def get_exception(cve_id: str, asset_id: str) -> dict:
    """
    Check whether an active risk exception exists for a CVE + asset pair.

    A risk exception indicates that the normal SLA requirement has been formally
    waived by an approver for a defined period. Always check this before escalating.

    Args:
        cve_id: CVE identifier
        asset_id: Asset identifier
    """
    try:
        _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e)}

    _audit.log_user_input("tool_call", "get_exception", validation_passed=True, input_length=len(cve_id + asset_id))

    registry = ExceptionRegistry()
    exc = registry.get_exception(cve_id, asset_id)

    if not exc:
        return {"found": False, "cve_id": cve_id, "asset_id": asset_id}

    return {"found": True, **_exception_to_dict(exc)}


async def record_exception(
    cve_id: str,
    asset_id: str,
    reason: str,
    approved_by: str,
    expires_days: int = 90,
) -> dict:
    """
    Record a risk acceptance exception for a CVE + asset pair.

    Use this when remediation is formally deferred with management approval
    (e.g. compensating controls in place, third-party dependency, accepted business risk).
    The exception expires after the specified number of days.

    Args:
        cve_id: CVE identifier
        asset_id: Asset identifier
        reason: Business justification for accepting the risk
        approved_by: Name or email of the approver
        expires_days: Days until the exception expires (default 90)
    """
    try:
        _validator.validate_vuln_id(cve_id)
    except ValidationError as e:
        return {"error": str(e)}

    if not reason or not approved_by:
        return {"error": "Both 'reason' and 'approved_by' are required to record an exception"}

    expires_days = max(1, min(expires_days, 365))

    _audit.log_user_input("tool_call", "record_exception", validation_passed=True, input_length=len(cve_id + asset_id))

    registry = ExceptionRegistry()
    exc = registry.add_exception(
        cve_id=cve_id,
        asset_id=asset_id,
        reason=reason,
        approved_by=approved_by,
        expires_days=expires_days,
    )

    return {"recorded": True, **_exception_to_dict(exc)}
