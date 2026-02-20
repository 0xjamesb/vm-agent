"""Risk exception registry — tracks accepted risks and granted SLA exceptions."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config.settings import get_settings


@dataclass
class RiskException:
    """A granted exception or risk acceptance for a specific CVE + asset combination."""

    id: str
    cve_id: str
    asset_id: str
    reason: str
    approved_by: str
    granted_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None  # None = permanent

    @property
    def is_active(self) -> bool:
        if self.expires_at is None:
            return True
        return datetime.now() < self.expires_at

    @property
    def days_remaining(self) -> Optional[int]:
        if self.expires_at is None:
            return None
        return (self.expires_at - datetime.now()).days


class ExceptionRegistry:
    """
    JSON-persisted registry of risk acceptances and SLA exceptions.

    When an exception exists for a (CVE, asset) pair, the normal SLA
    and remediation workflow is suspended until the exception expires.
    """

    def __init__(self, persistence_path: Optional[Path] = None):
        settings = get_settings()
        self.persistence_path = persistence_path or (settings.data_dir / "exceptions.json")
        self._exceptions: dict[str, RiskException] = {}

        if self.persistence_path.exists():
            self._load()

    def _to_dict(self, exc: RiskException) -> dict:
        return {
            "id": exc.id,
            "cve_id": exc.cve_id,
            "asset_id": exc.asset_id,
            "reason": exc.reason,
            "approved_by": exc.approved_by,
            "granted_at": exc.granted_at.isoformat(),
            "expires_at": exc.expires_at.isoformat() if exc.expires_at else None,
        }

    def _from_dict(self, d: dict) -> RiskException:
        return RiskException(
            id=d["id"],
            cve_id=d["cve_id"],
            asset_id=d["asset_id"],
            reason=d["reason"],
            approved_by=d["approved_by"],
            granted_at=datetime.fromisoformat(d["granted_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
        )

    def _load(self):
        with open(self.persistence_path) as f:
            data = json.load(f)
        for item in data.get("exceptions", []):
            exc = self._from_dict(item)
            self._exceptions[exc.id] = exc

    def _save(self):
        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"exceptions": [self._to_dict(e) for e in self._exceptions.values()]}
        with open(self.persistence_path, "w") as f:
            json.dump(data, f, indent=2)

    def get_exception(self, cve_id: str, asset_id: str) -> Optional[RiskException]:
        """Return the active exception for a CVE + asset pair, or None."""
        for exc in self._exceptions.values():
            if exc.cve_id == cve_id and exc.asset_id == asset_id and exc.is_active:
                return exc
        return None

    def add_exception(
        self,
        cve_id: str,
        asset_id: str,
        reason: str,
        approved_by: str,
        expires_days: int = 90,
    ) -> RiskException:
        """Record a new risk acceptance. Replaces any existing active exception for the same pair."""
        exc = RiskException(
            id=str(uuid.uuid4()),
            cve_id=cve_id,
            asset_id=asset_id,
            reason=reason,
            approved_by=approved_by,
            expires_at=datetime.now() + timedelta(days=expires_days),
        )
        self._exceptions[exc.id] = exc
        self._save()
        return exc

    def list_exceptions(self, active_only: bool = True) -> list[RiskException]:
        """List all exceptions, optionally filtered to active ones only."""
        results = list(self._exceptions.values())
        if active_only:
            results = [e for e in results if e.is_active]
        return sorted(results, key=lambda e: e.granted_at, reverse=True)
