"""Unit tests for the DNS lookup module."""

import pytest
from unittest.mock import patch, MagicMock
from modules.dns_lookup import run, _extract_record_value


class TestExtractRecordValue:
    """Tests for the record value extraction helper."""

    def test_a_record(self):
        rdata = MagicMock()
        rdata.address = "93.184.216.34"
        assert _extract_record_value("A", rdata) == "93.184.216.34"

    def test_aaaa_record(self):
        rdata = MagicMock()
        rdata.address = "2606:2800:220:1:248:1893:25c8:1946"
        assert _extract_record_value("AAAA", rdata) == "2606:2800:220:1:248:1893:25c8:1946"

    def test_mx_record(self):
        rdata = MagicMock()
        rdata.preference = 10
        rdata.exchange.to_text.return_value = "mail.example.com."
        result = _extract_record_value("MX", rdata)
        assert "10" in result
        assert "mail.example.com" in result

    def test_ns_record(self):
        rdata = MagicMock()
        rdata.target.to_text.return_value = "ns1.example.com."
        assert _extract_record_value("NS", rdata) == "ns1.example.com."

    def test_txt_record(self):
        rdata = MagicMock()
        rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]
        result = _extract_record_value("TXT", rdata)
        assert "v=spf1" in result


class TestDnsLookupRun:
    """Tests for the main DNS lookup function."""

    @patch("modules.dns_lookup._create_resolver")
    def test_returns_domain(self, mock_resolver_factory):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("no records")
        mock_resolver_factory.return_value = mock_resolver

        results = run("example.com")
        assert results["domain"] == "example.com"

    @patch("modules.dns_lookup._create_resolver")
    def test_handles_nxdomain(self, mock_resolver_factory):
        import dns.resolver
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_factory.return_value = mock_resolver

        results = run("nonexistent.invalid")
        assert "error" in results

    @patch("modules.dns_lookup._create_resolver")
    def test_a_records_populated(self, mock_resolver_factory):
        mock_resolver = MagicMock()

        # Build mock A record answer
        mock_rdata = MagicMock()
        mock_rdata.address = "1.2.3.4"
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
        mock_answer.rrset = mock_rrset

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return mock_answer
            raise Exception("not mocked")

        mock_resolver.resolve.side_effect = resolve_side_effect
        mock_resolver_factory.return_value = mock_resolver

        results = run("example.com")
        assert len(results["A"]) == 1
        assert results["A"][0]["value"] == "1.2.3.4"
        assert results["A"][0]["ttl"] == 300
