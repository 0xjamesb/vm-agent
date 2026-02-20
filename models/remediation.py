from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class RemediationStatus(Enum):
    """Status of a remediation task."""

    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"  # Risk accepted, won't fix
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class RemediationTask:
    """Tracks remediation of a vulnerability on an asset."""

    id: str
    vulnerability_id: str
    asset_id: str
    status: RemediationStatus = RemediationStatus.OPEN

    # Assignment
    assigned_team: Optional[str] = None
    assigned_to: Optional[str] = None

    # Tracking
    created_at: datetime = field(default_factory=datetime.now)
    due_date: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Communication
    justification_sent: bool = False
    ticket_id: Optional[str] = None  # External ticket system ID

    # Notes
    notes: list[str] = field(default_factory=list)

    @property
    def is_overdue(self) -> bool:
        """Check if this task is past its due date."""
        if self.due_date is None:
            return False
        if self.status in (RemediationStatus.RESOLVED, RemediationStatus.ACCEPTED_RISK):
            return False
        return datetime.now() > self.due_date

    @property
    def days_until_due(self) -> Optional[int]:
        """Days until due date (negative if overdue)."""
        if self.due_date is None:
            return None
        delta = self.due_date - datetime.now()
        return delta.days
