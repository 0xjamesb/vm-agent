from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class TicketStatus(Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


@dataclass
class Ticket:
    """A ticket in an external ticketing system."""

    id: str
    title: str
    description: str
    status: TicketStatus = TicketStatus.OPEN
    priority: str = "Medium"
    assignee: Optional[str] = None
    labels: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    external_url: Optional[str] = None

    # Link back to our data
    vulnerability_id: Optional[str] = None
    asset_id: Optional[str] = None


class TicketingSystem(ABC):
    """Abstract base class for ticketing system integrations."""

    @abstractmethod
    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str = "Medium",
        assignee: Optional[str] = None,
        labels: Optional[list[str]] = None,
        vulnerability_id: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> Ticket:
        """Create a new ticket."""
        pass

    @abstractmethod
    async def update_ticket(
        self,
        ticket_id: str,
        status: Optional[TicketStatus] = None,
        assignee: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Ticket:
        """Update an existing ticket."""
        pass

    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        """Get a ticket by ID."""
        pass

    @abstractmethod
    async def find_tickets(
        self,
        vulnerability_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        status: Optional[TicketStatus] = None,
    ) -> list[Ticket]:
        """Find tickets matching criteria."""
        pass
