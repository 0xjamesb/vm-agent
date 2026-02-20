"""Tests for the risk exception registry."""

import pytest
from datetime import datetime, timedelta

from integrations.exceptions.registry import ExceptionRegistry, RiskException


@pytest.fixture
def tmp_registry(tmp_path):
    return ExceptionRegistry(persistence_path=tmp_path / "exceptions.json")


class TestExceptionRegistry:
    def test_empty_on_first_run(self, tmp_registry):
        assert tmp_registry.list_exceptions() == []

    def test_add_exception(self, tmp_registry):
        exc = tmp_registry.add_exception(
            cve_id="CVE-2021-23337",
            asset_id="asset-auth-service",
            reason="Compensating control in place",
            approved_by="CISO",
            expires_days=30,
        )
        assert exc.cve_id == "CVE-2021-23337"
        assert exc.asset_id == "asset-auth-service"
        assert exc.is_active

    def test_get_active_exception(self, tmp_registry):
        tmp_registry.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO")
        exc = tmp_registry.get_exception("CVE-2021-23337", "asset-auth-service")
        assert exc is not None

    def test_get_exception_wrong_asset_returns_none(self, tmp_registry):
        tmp_registry.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO")
        assert tmp_registry.get_exception("CVE-2021-23337", "asset-payment-api") is None

    def test_expired_exception_not_returned(self, tmp_path):
        registry = ExceptionRegistry(persistence_path=tmp_path / "exc.json")
        exc = registry.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO", expires_days=1)
        # Manually expire it
        exc.expires_at = datetime.now() - timedelta(days=1)
        registry._exceptions[exc.id] = exc

        result = registry.get_exception("CVE-2021-23337", "asset-auth-service")
        assert result is None

    def test_list_active_only(self, tmp_path):
        registry = ExceptionRegistry(persistence_path=tmp_path / "exc.json")
        active = registry.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO", expires_days=30)
        expired = registry.add_exception("CVE-2020-28500", "asset-auth-service", "test", "CISO", expires_days=1)
        expired.expires_at = datetime.now() - timedelta(days=1)
        registry._exceptions[expired.id] = expired

        active_list = registry.list_exceptions(active_only=True)
        assert len(active_list) == 1
        assert active_list[0].id == active.id

    def test_persistence(self, tmp_path):
        path = tmp_path / "exc.json"
        r1 = ExceptionRegistry(persistence_path=path)
        r1.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO")

        r2 = ExceptionRegistry(persistence_path=path)
        assert r2.get_exception("CVE-2021-23337", "asset-auth-service") is not None

    def test_days_remaining(self, tmp_registry):
        exc = tmp_registry.add_exception("CVE-2021-23337", "asset-auth-service", "test", "CISO", expires_days=30)
        assert exc.days_remaining is not None
        assert 28 <= exc.days_remaining <= 30
