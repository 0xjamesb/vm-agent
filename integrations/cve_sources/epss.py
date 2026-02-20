from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import httpx


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""

    cve_id: str
    epss: float  # Probability of exploitation (0.0 - 1.0)
    percentile: float  # Percentile ranking (0.0 - 1.0)
    date: datetime


class EPSSClient:
    """
    Client for the EPSS (Exploit Prediction Scoring System) API.

    EPSS provides a probability score (0-1) indicating how likely a CVE
    is to be exploited in the next 30 days. This is based on real-world
    exploitation data and vulnerability characteristics.

    API Documentation: https://www.first.org/epss/api
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def get_score(self, cve_id: str) -> Optional[EPSSScore]:
        """
        Get the EPSS score for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            EPSSScore if available, None otherwise.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                self.BASE_URL,
                params={"cve": cve_id.upper()}
            )
            response.raise_for_status()
            data = response.json()

        results = data.get("data", [])
        if not results:
            return None

        result = results[0]
        return EPSSScore(
            cve_id=result["cve"],
            epss=float(result["epss"]),
            percentile=float(result["percentile"]),
            date=datetime.fromisoformat(data.get("score_date", datetime.now().isoformat())),
        )

    async def get_scores_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """
        Get EPSS scores for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dictionary mapping CVE IDs to their EPSS scores.
        """
        if not cve_ids:
            return {}

        # EPSS API accepts comma-separated CVEs
        cve_param = ",".join(cve.upper() for cve in cve_ids)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                self.BASE_URL,
                params={"cve": cve_param}
            )
            response.raise_for_status()
            data = response.json()

        scores = {}
        score_date = data.get("score_date", datetime.now().isoformat())

        for result in data.get("data", []):
            cve_id = result["cve"]
            scores[cve_id] = EPSSScore(
                cve_id=cve_id,
                epss=float(result["epss"]),
                percentile=float(result["percentile"]),
                date=datetime.fromisoformat(score_date),
            )

        return scores

    async def get_high_risk(
        self,
        percentile_threshold: float = 0.9,
        limit: int = 100,
    ) -> list[EPSSScore]:
        """
        Get CVEs with EPSS scores above a percentile threshold.

        Args:
            percentile_threshold: Minimum percentile (0.9 = top 10%)
            limit: Maximum number of results.

        Returns:
            List of high-risk EPSS scores.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                self.BASE_URL,
                params={
                    "percentile-gt": percentile_threshold,
                    "limit": limit,
                    "order": "!epss",  # Descending by EPSS score
                }
            )
            response.raise_for_status()
            data = response.json()

        scores = []
        score_date = data.get("score_date", datetime.now().isoformat())

        for result in data.get("data", []):
            scores.append(
                EPSSScore(
                    cve_id=result["cve"],
                    epss=float(result["epss"]),
                    percentile=float(result["percentile"]),
                    date=datetime.fromisoformat(score_date),
                )
            )

        return scores

    @staticmethod
    def interpret_score(epss_score: float) -> str:
        """
        Provide human-readable interpretation of an EPSS score.

        Args:
            epss_score: EPSS probability (0.0 - 1.0)

        Returns:
            Human-readable risk description.
        """
        if epss_score >= 0.5:
            return "Very High - Exploitation highly likely within 30 days"
        elif epss_score >= 0.2:
            return "High - Significant probability of exploitation"
        elif epss_score >= 0.05:
            return "Moderate - Notable exploitation probability"
        elif epss_score >= 0.01:
            return "Low - Some exploitation risk"
        else:
            return "Very Low - Minimal exploitation probability"
