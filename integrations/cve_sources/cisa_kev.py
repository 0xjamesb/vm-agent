from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import httpx


@dataclass
class KEVEntry:
    """A single entry from the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: datetime
    short_description: str
    required_action: str
    due_date: datetime
    known_ransomware_use: bool
    notes: str = ""


class CISAKEVClient:
    """
    Client for the CISA Known Exploited Vulnerabilities (KEV) catalog.

    The KEV catalog contains CVEs that are known to be actively exploited
    in the wild. This is a critical signal for prioritization.

    Data source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._cache: Optional[dict[str, KEVEntry]] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl_seconds = 3600  # 1 hour

    async def _fetch_catalog(self) -> dict[str, KEVEntry]:
        """Fetch the full KEV catalog."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(self.CATALOG_URL)
            response.raise_for_status()
            data = response.json()

        catalog = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            # Parse dates
            date_added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
            due_date = datetime.strptime(vuln["dueDate"], "%Y-%m-%d")

            catalog[cve_id] = KEVEntry(
                cve_id=cve_id,
                vendor_project=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                vulnerability_name=vuln.get("vulnerabilityName", ""),
                date_added=date_added,
                short_description=vuln.get("shortDescription", ""),
                required_action=vuln.get("requiredAction", ""),
                due_date=due_date,
                known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "").lower() == "known",
                notes=vuln.get("notes", ""),
            )

        return catalog

    async def _get_catalog(self) -> dict[str, KEVEntry]:
        """Get catalog with caching."""
        now = datetime.now()

        if (
            self._cache is None
            or self._cache_time is None
            or (now - self._cache_time).seconds > self._cache_ttl_seconds
        ):
            self._cache = await self._fetch_catalog()
            self._cache_time = now

        return self._cache

    async def is_in_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            True if the CVE is in the KEV catalog.
        """
        catalog = await self._get_catalog()
        return cve_id.upper() in catalog

    async def get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """
        Get the KEV entry for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            KEVEntry if found, None otherwise.
        """
        catalog = await self._get_catalog()
        return catalog.get(cve_id.upper())

    async def get_all_kev_entries(self) -> list[KEVEntry]:
        """Get all entries in the KEV catalog."""
        catalog = await self._get_catalog()
        return list(catalog.values())

    async def get_recent_additions(self, days: int = 30) -> list[KEVEntry]:
        """
        Get KEV entries added in the last N days.

        Args:
            days: Number of days to look back.

        Returns:
            List of KEV entries added within the timeframe.
        """
        catalog = await self._get_catalog()
        cutoff = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff = cutoff.replace(day=cutoff.day - days) if cutoff.day > days else cutoff

        recent = [
            entry for entry in catalog.values()
            if entry.date_added >= cutoff
        ]

        return sorted(recent, key=lambda e: e.date_added, reverse=True)

    async def get_ransomware_associated(self) -> list[KEVEntry]:
        """Get KEV entries known to be associated with ransomware campaigns."""
        catalog = await self._get_catalog()
        return [
            entry for entry in catalog.values()
            if entry.known_ransomware_use
        ]
