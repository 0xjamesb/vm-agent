from abc import ABC, abstractmethod
from typing import Optional

from models import Vulnerability


class VulnerabilitySource(ABC):
    """Abstract base class for vulnerability data sources."""

    @abstractmethod
    async def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Fetch a specific vulnerability by ID (CVE, GHSA, etc.)."""
        pass

    @abstractmethod
    async def query_package(
        self,
        ecosystem: str,
        package_name: str,
        version: Optional[str] = None,
    ) -> list[Vulnerability]:
        """Query vulnerabilities affecting a specific package."""
        pass

    @abstractmethod
    async def get_recent(self, limit: int = 100) -> list[Vulnerability]:
        """Get recently published/modified vulnerabilities."""
        pass
