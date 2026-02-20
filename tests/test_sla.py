"""Tests for SLA policy configuration."""

from datetime import datetime, timedelta

import pytest

from config.sla import describe_sla, get_due_date, get_sla_days, SLA_POLICY


class TestGetSlaDays:
    def test_critical_kev(self):
        assert get_sla_days("CRITICAL", True) == 1

    def test_critical_no_kev(self):
        assert get_sla_days("CRITICAL", False) == 7

    def test_high_kev(self):
        assert get_sla_days("HIGH", True) == 3

    def test_high_no_kev(self):
        assert get_sla_days("HIGH", False) == 14

    def test_medium_kev(self):
        assert get_sla_days("MEDIUM", True) == 7

    def test_medium_no_kev(self):
        assert get_sla_days("MEDIUM", False) == 30

    def test_low_kev(self):
        assert get_sla_days("LOW", True) == 14

    def test_low_no_kev(self):
        assert get_sla_days("LOW", False) == 90

    def test_unknown_severity_returns_default(self):
        assert get_sla_days("UNKNOWN", False) == 30

    def test_case_insensitive(self):
        assert get_sla_days("critical", True) == get_sla_days("CRITICAL", True)


class TestGetDueDate:
    def test_returns_future_date(self):
        due = get_due_date("HIGH", False)
        assert due > datetime.now()

    def test_correct_offset_from_today(self):
        now = datetime.now()
        due = get_due_date("HIGH", False)
        expected_days = get_sla_days("HIGH", False)
        delta = (due - now).days
        assert delta == expected_days

    def test_custom_from_date(self):
        base = datetime(2025, 1, 1)
        due = get_due_date("CRITICAL", False, from_date=base)
        assert due == base + timedelta(days=7)


class TestDescribeSla:
    def test_24h_description(self):
        desc = describe_sla("CRITICAL", True)
        assert "24 hours" in desc
        assert "CRITICAL" in desc

    def test_days_description(self):
        desc = describe_sla("HIGH", False)
        assert "14 days" in desc

    def test_kev_note_included(self):
        desc = describe_sla("HIGH", True)
        assert "KEV" in desc or "exploited" in desc.lower()

    def test_no_kev_note_when_not_kev(self):
        desc = describe_sla("MEDIUM", False)
        assert "KEV" not in desc
