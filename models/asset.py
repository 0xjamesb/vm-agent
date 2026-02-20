from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AssetCriticality(Enum):
    """Business criticality of an asset."""

    CRITICAL = "CRITICAL"  # Revenue-generating, customer-facing, auth systems
    HIGH = "HIGH"  # Important internal systems
    MEDIUM = "MEDIUM"  # Standard business systems
    LOW = "LOW"  # Development, testing, non-essential


@dataclass
class Asset:
    """
    Represents a service, application, or system that may have vulnerabilities.
    """

    id: str
    name: str
    description: str = ""
    owner_team: Optional[str] = None
    owner_contact: Optional[str] = None  # Email or Slack handle
    criticality: AssetCriticality = AssetCriticality.MEDIUM

    # Technology stack
    ecosystem: Optional[str] = None  # e.g., "npm", "PyPI"
    dependencies: list[dict] = field(default_factory=list)  # [{name, version}]

    # Compliance context
    compliance_scope: list[str] = field(default_factory=list)  # e.g., ["PCI-DSS", "SOC2"]
    data_classification: Optional[str] = None  # e.g., "PII", "Financial"

    @property
    def criticality_multiplier(self) -> float:
        """Multiplier for priority calculations based on asset criticality."""
        return {
            AssetCriticality.CRITICAL: 2.0,
            AssetCriticality.HIGH: 1.5,
            AssetCriticality.MEDIUM: 1.0,
            AssetCriticality.LOW: 0.5,
        }[self.criticality]
