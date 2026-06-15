"""Unit tests for the WHOIS lookup module."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from modules.whois_lookup import run, _normalize_date, _normalize_list


class TestNormalizeDate:
    """Tests for the date normalization helper."""

    def test_none_returns_none(self):
        assert _normalize_date(None) is None

    def test_datetime_formatted(self):
        dt = datetime(2025, 6, 15, 12, 0, 0)
        assert _normalize_date(dt) == "2025-06-15 12:00:00"

    def test_list_takes_first(self):
        dt1 = datetime(2020, 1, 1)
        dt2 = datetime(2021, 1, 1)
        result = _normalize_date([dt1, dt2])
        assert "2020-01-01" in result

    def test_string_passthrough(self):
        assert _normalize_date("2023-01-01") == "2023-01-01"


class TestNormalizeList:
    """Tests for the list normalization helper."""

    def test_none_returns_empty(self):
        assert _normalize_list(None) == []

    def test_string_wrapped(self):
        assert _normalize_list("ns1.google.com") == ["ns1.google.com"]

    def test_list_preserved(self):
        result = _normalize_list(["ns1.google.com", "ns2.google.com"])
        assert len(result) == 2


class TestWhoisRun:
    """Tests for the main WHOIS lookup function."""

    @patch("modules.whois_lookup.whois.whois")
    def test_successful_lookup(self, mock_whois):
        mock_data = MagicMock()
        mock_data.registrar = "Example Registrar Inc."
        mock_data.org = "Example Org"
        mock_data.country = "US"
        mock_data.creation_date = datetime(2000, 1, 1)
        mock_data.updated_date = datetime(2024, 6, 1)
        mock_data.expiration_date = datetime(2030, 1, 1)
        mock_data.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_data.status = ["clientTransferProhibited"]
        mock_whois.return_value = mock_data

        results = run("example.com")

        assert results["domain"] == "example.com"
        assert results["registrar"] == "Example Registrar Inc."
        assert results["organization"] == "Example Org"
        assert results["country"] == "US"
        assert results["error"] is None
        assert len(results["name_servers"]) == 2

    @patch("modules.whois_lookup.whois.whois")
    def test_lookup_failure(self, mock_whois):
        mock_whois.side_effect = Exception("WHOIS server unavailable")

        results = run("nonexistent.invalid")

        assert results["error"] is not None
        assert "unavailable" in results["error"]

    @patch("modules.whois_lookup.whois.whois")
    def test_missing_optional_fields(self, mock_whois):
        mock_data = MagicMock()
        mock_data.registrar = None
        mock_data.org = None
        mock_data.country = None
        mock_data.creation_date = None
        mock_data.updated_date = None
        mock_data.expiration_date = None
        mock_data.name_servers = None
        mock_data.status = None
        mock_whois.return_value = mock_data

        results = run("minimal.com")

        assert results["registrar"] is None
        assert results["name_servers"] == []
        assert results["error"] is None
