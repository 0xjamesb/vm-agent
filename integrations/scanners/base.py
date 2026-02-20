from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from models import Vulnerability


@dataclass
class ScanResult:
    """Result of a vulnerability scan."""

    scan_id: str
    asset_id: str
    timestamp: datetime
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scanner_name: str = ""
    raw_data: Optional[dict] = None


class Scanner(ABC):
    """Abstract base class for vulnerability scanners."""

    @abstractmethod
    async def scan_asset(self, asset_id: str) -> ScanResult:
        """Run a scan on a specific asset."""
        pass

    @abstractmethod
    async def get_scan_results(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve results from a previous scan."""
        pass

    @abstractmethod
    async def list_recent_scans(self, limit: int = 100) -> list[ScanResult]:
        """List recent scan results."""
        pass
