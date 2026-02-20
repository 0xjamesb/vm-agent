"""
Mock ticketing system for development and testing.

Stores tickets in memory with optional JSON persistence.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import TicketingSystem, Ticket, TicketStatus


class MockTicketingSystem(TicketingSystem):
    """
    In-memory ticketing system for development.

    Optionally persists to a JSON file for testing continuity.
    """

    def __init__(self, persistence_path: Optional[Path] = None):
        self.persistence_path = persistence_path
        self._tickets: dict[str, Ticket] = {}

        if persistence_path and persistence_path.exists():
            self._load()

    def _load(self):
        """Load tickets from JSON file."""
        if not self.persistence_path:
            return

        with open(self.persistence_path) as f:
            data = json.load(f)

        for ticket_data in data.get("tickets", []):
            ticket = Ticket(
                id=ticket_data["id"],
                title=ticket_data["title"],
                description=ticket_data["description"],
                status=TicketStatus(ticket_data["status"]),
                priority=ticket_data["priority"],
                assignee=ticket_data.get("assignee"),
                labels=ticket_data.get("labels", []),
                created_at=datetime.fromisoformat(ticket_data["created_at"]),
                updated_at=datetime.fromisoformat(ticket_data["updated_at"]),
                vulnerability_id=ticket_data.get("vulnerability_id"),
                asset_id=ticket_data.get("asset_id"),
            )
            self._tickets[ticket.id] = ticket

    def _save(self):
        """Save tickets to JSON file."""
        if not self.persistence_path:
            return

        data = {
            "tickets": [
                {
                    "id": t.id,
                    "title": t.title,
                    "description": t.description,
                    "status": t.status.value,
                    "priority": t.priority,
                    "assignee": t.assignee,
                    "labels": t.labels,
                    "created_at": t.created_at.isoformat(),
                    "updated_at": t.updated_at.isoformat(),
                    "vulnerability_id": t.vulnerability_id,
                    "asset_id": t.asset_id,
                }
                for t in self._tickets.values()
            ]
        }

        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.persistence_path, "w") as f:
            json.dump(data, f, indent=2)

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
        ticket = Ticket(
            id=f"MOCK-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            description=description,
            priority=priority,
            assignee=assignee,
            labels=labels or [],
            vulnerability_id=vulnerability_id,
            asset_id=asset_id,
        )

        self._tickets[ticket.id] = ticket
        self._save()
        return ticket

    async def update_ticket(
        self,
        ticket_id: str,
        status: Optional[TicketStatus] = None,
        assignee: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Ticket:
        """Update an existing ticket."""
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            raise ValueError(f"Ticket {ticket_id} not found")

        if status:
            ticket.status = status
        if assignee:
            ticket.assignee = assignee
        ticket.updated_at = datetime.now()

        self._save()
        return ticket

    async def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        """Get a ticket by ID."""
        return self._tickets.get(ticket_id)

    async def find_tickets(
        self,
        vulnerability_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        status: Optional[TicketStatus] = None,
    ) -> list[Ticket]:
        """Find tickets matching criteria."""
        results = []

        for ticket in self._tickets.values():
            if vulnerability_id and ticket.vulnerability_id != vulnerability_id:
                continue
            if asset_id and ticket.asset_id != asset_id:
                continue
            if status and ticket.status != status:
                continue
            results.append(ticket)

        return results
