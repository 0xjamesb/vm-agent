"""SLA policy configuration for vulnerability remediation timelines."""

from __future__ import annotations

from datetime import datetime, timedelta

# (severity, in_kev) → days to remediate
# Industry standard defaults — adjust to match your organization's policy
SLA_POLICY: dict[tuple[str, bool], int] = {
    ("CRITICAL", True):  1,   # CRITICAL + actively exploited (KEV) → 24 hours
    ("CRITICAL", False): 7,   # CRITICAL → 7 days
    ("HIGH",     True):  3,   # HIGH + actively exploited → 3 days
    ("HIGH",     False): 14,  # HIGH → 14 days
    ("MEDIUM",   True):  7,   # MEDIUM + actively exploited → 7 days
    ("MEDIUM",   False): 30,  # MEDIUM → 30 days
    ("LOW",      True):  14,  # LOW + actively exploited → 14 days
    ("LOW",      False): 90,  # LOW → 90 days
}

_DEFAULT_SLA_DAYS = 30  # Fallback for UNKNOWN severity


def get_sla_days(severity: str, in_kev: bool = False) -> int:
    """Return the number of days allowed to remediate based on severity and KEV status."""
    key = (severity.upper(), in_kev)
    return SLA_POLICY.get(key, _DEFAULT_SLA_DAYS)


def get_due_date(
    severity: str,
    in_kev: bool = False,
    from_date: datetime | None = None,
) -> datetime:
    """Return the remediation due date based on SLA policy."""
    start = from_date or datetime.now()
    days = get_sla_days(severity, in_kev)
    return start + timedelta(days=days)


def describe_sla(severity: str, in_kev: bool = False) -> str:
    """Return a human-readable description of the applicable SLA."""
    days = get_sla_days(severity, in_kev)
    kev_note = " (actively exploited — CISA KEV)" if in_kev else ""
    if days == 1:
        return f"{severity}{kev_note}: remediate within 24 hours"
    return f"{severity}{kev_note}: remediate within {days} days"
