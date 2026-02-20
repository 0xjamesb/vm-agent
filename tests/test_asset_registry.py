"""Tests for the asset registry."""

import json
import pytest
from pathlib import Path

from integrations.assets.registry import AssetRegistry
from models.asset import Asset, AssetCriticality


@pytest.fixture
def tmp_registry(tmp_path):
    """AssetRegistry backed by a temp file."""
    return AssetRegistry(persistence_path=tmp_path / "assets.json")


class TestAssetRegistry:
    def test_seeded_on_first_run(self, tmp_registry):
        assets = tmp_registry.list_assets()
        assert len(assets) >= 5

    def test_get_existing_asset(self, tmp_registry):
        asset = tmp_registry.get_asset("asset-payment-api")
        assert asset is not None
        assert asset.name == "Payment API"
        assert asset.criticality == AssetCriticality.CRITICAL

    def test_get_missing_asset_returns_none(self, tmp_registry):
        assert tmp_registry.get_asset("nonexistent-asset") is None

    def test_upsert_new_asset(self, tmp_registry):
        new_asset = Asset(
            id="asset-test-service",
            name="Test Service",
            criticality=AssetCriticality.LOW,
            owner_team="QA",
        )
        saved = tmp_registry.upsert_asset(new_asset)
        assert saved.id == "asset-test-service"
        assert tmp_registry.get_asset("asset-test-service") is not None

    def test_upsert_updates_existing(self, tmp_registry):
        asset = tmp_registry.get_asset("asset-payment-api")
        asset.owner_team = "New Payments Team"
        tmp_registry.upsert_asset(asset)
        updated = tmp_registry.get_asset("asset-payment-api")
        assert updated.owner_team == "New Payments Team"

    def test_list_filter_by_team(self, tmp_registry):
        results = tmp_registry.list_assets(team="Payments")
        assert all("Payments" in (a.owner_team or "") for a in results)
        assert len(results) >= 1

    def test_list_filter_by_ecosystem(self, tmp_registry):
        results = tmp_registry.list_assets(ecosystem="npm")
        assert all(a.ecosystem == "npm" for a in results)

    def test_persistence(self, tmp_path):
        path = tmp_path / "assets.json"
        r1 = AssetRegistry(persistence_path=path)
        r1.upsert_asset(Asset(id="persist-test", name="Persist Test", criticality=AssetCriticality.HIGH))

        r2 = AssetRegistry(persistence_path=path)
        assert r2.get_asset("persist-test") is not None
