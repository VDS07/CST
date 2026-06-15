"""Unit tests for the security headers checker module."""

import pytest
from unittest.mock import patch, MagicMock
from modules.header_checker import run, SECURITY_HEADERS


class TestHeaderCheckerRun:
    """Tests for the main header checker function."""

    @patch("modules.header_checker.requests.get")
    def test_all_headers_present(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
        mock_get.return_value = mock_response

        results = run("https://secure-site.com")

        assert results["error"] is None
        assert results["score"] == len(SECURITY_HEADERS)
        for h in results["headers"]:
            assert h["present"] is True

    @patch("modules.header_checker.requests.get")
    def test_no_headers_present(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_get.return_value = mock_response

        results = run("https://bare-site.com")

        assert results["score"] == 0
        for h in results["headers"]:
            assert h["present"] is False

    @patch("modules.header_checker.requests.get")
    def test_partial_headers(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=300",
            "X-Frame-Options": "SAMEORIGIN",
        }
        mock_get.return_value = mock_response

        results = run("example.com")

        assert results["score"] == 2
        assert results["error"] is None

    @patch("modules.header_checker.requests.get")
    def test_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")

        results = run("unreachable.invalid")

        assert results["error"] is not None
        assert "Connection failed" in results["error"]

    @patch("modules.header_checker.requests.get")
    def test_timeout_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.Timeout()

        results = run("slow-site.com")

        assert results["error"] is not None
        assert "timed out" in results["error"]

    @patch("modules.header_checker.requests.get")
    def test_severity_assigned(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_get.return_value = mock_response

        results = run("example.com")

        severities = {h["severity"] for h in results["headers"]}
        assert "Critical" in severities
        assert "Warning" in severities

    def test_url_normalization(self):
        """Verify that plain domains get https:// prepended."""
        with patch("modules.header_checker.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {}
            mock_get.return_value = mock_response

            results = run("example.com")
            assert results["target"] == "https://example.com"
