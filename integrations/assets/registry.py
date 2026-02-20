"""Asset registry — JSON-persisted store of known assets and their metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from models.asset import Asset, AssetCriticality
from config.settings import get_settings

# Sample assets seeded on first run so the system is immediately usable
_SEED_ASSETS: list[dict] = [
    {
        "id": "asset-payment-api",
        "name": "Payment API",
        "description": "Core payment processing service handling all transactions",
        "owner_team": "Payments",
        "owner_contact": "payments-team@example.com",
        "criticality": "CRITICAL",
        "ecosystem": "PyPI",
        "dependencies": [{"name": "requests", "version": "2.28.0"}, {"name": "cryptography", "version": "38.0.0"}],
        "compliance_scope": ["PCI-DSS", "SOC2"],
        "data_classification": "Financial",
    },
    {
        "id": "asset-auth-service",
        "name": "Auth Service",
        "description": "Authentication and authorization service (OAuth2 / JWT)",
        "owner_team": "Platform",
        "owner_contact": "platform-eng@example.com",
        "criticality": "CRITICAL",
        "ecosystem": "npm",
        "dependencies": [{"name": "jsonwebtoken", "version": "8.5.1"}, {"name": "lodash", "version": "4.17.20"}],
        "compliance_scope": ["SOC2"],
        "data_classification": "PII",
    },
    {
        "id": "asset-data-pipeline",
        "name": "Data Pipeline",
        "description": "ETL pipeline for analytics and reporting",
        "owner_team": "Data Engineering",
        "owner_contact": "data-eng@example.com",
        "criticality": "HIGH",
        "ecosystem": "PyPI",
        "dependencies": [{"name": "numpy", "version": "1.23.0"}, {"name": "pandas", "version": "1.5.0"}],
        "compliance_scope": [],
        "data_classification": "Internal",
    },
    {
        "id": "asset-customer-portal",
        "name": "Customer Portal",
        "description": "Customer-facing web application",
        "owner_team": "Frontend",
        "owner_contact": "frontend-team@example.com",
        "criticality": "HIGH",
        "ecosystem": "npm",
        "dependencies": [{"name": "react", "version": "18.2.0"}, {"name": "axios", "version": "0.27.0"}],
        "compliance_scope": ["SOC2"],
        "data_classification": "PII",
    },
    {
        "id": "asset-internal-tools",
        "name": "Internal Tools",
        "description": "Internal developer tooling and dashboards",
        "owner_team": "Engineering",
        "owner_contact": "eng-leads@example.com",
        "criticality": "LOW",
        "ecosystem": "npm",
        "dependencies": [{"name": "express", "version": "4.18.0"}],
        "compliance_scope": [],
        "data_classification": "Internal",
    },
]


class AssetRegistry:
    """
    JSON-persisted registry of assets (services, applications, infrastructure).

    Seeded with sample assets on first run. Analysts can add/update assets
    via the register_asset MCP tool as they discover new components.
    """

    def __init__(self, persistence_path: Optional[Path] = None):
        settings = get_settings()
        self.persistence_path = persistence_path or settings.assets_path
        self._assets: dict[str, Asset] = {}

        if self.persistence_path.exists():
            self._load()
        else:
            self._seed()
            self._save()

    def _asset_to_dict(self, asset: Asset) -> dict:
        return {
            "id": asset.id,
            "name": asset.name,
            "description": asset.description,
            "owner_team": asset.owner_team,
            "owner_contact": asset.owner_contact,
            "criticality": asset.criticality.value,
            "ecosystem": asset.ecosystem,
            "dependencies": asset.dependencies,
            "compliance_scope": asset.compliance_scope,
            "data_classification": asset.data_classification,
        }

    def _asset_from_dict(self, d: dict) -> Asset:
        return Asset(
            id=d["id"],
            name=d["name"],
            description=d.get("description", ""),
            owner_team=d.get("owner_team"),
            owner_contact=d.get("owner_contact"),
            criticality=AssetCriticality(d.get("criticality", "MEDIUM")),
            ecosystem=d.get("ecosystem"),
            dependencies=d.get("dependencies", []),
            compliance_scope=d.get("compliance_scope", []),
            data_classification=d.get("data_classification"),
        )

    def _load(self):
        with open(self.persistence_path) as f:
            data = json.load(f)
        for item in data.get("assets", []):
            asset = self._asset_from_dict(item)
            self._assets[asset.id] = asset

    def _save(self):
        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"assets": [self._asset_to_dict(a) for a in self._assets.values()]}
        with open(self.persistence_path, "w") as f:
            json.dump(data, f, indent=2)

    def _seed(self):
        for item in _SEED_ASSETS:
            asset = self._asset_from_dict(item)
            self._assets[asset.id] = asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        return self._assets.get(asset_id)

    def list_assets(self, team: str = "", ecosystem: str = "") -> list[Asset]:
        results = list(self._assets.values())
        if team:
            results = [a for a in results if a.owner_team and team.lower() in a.owner_team.lower()]
        if ecosystem:
            results = [a for a in results if a.ecosystem and ecosystem.lower() == a.ecosystem.lower()]
        return sorted(results, key=lambda a: a.criticality.value)

    def upsert_asset(self, asset: Asset) -> Asset:
        self._assets[asset.id] = asset
        self._save()
        return asset
