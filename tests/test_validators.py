"""Unit tests for the validators utility module."""

import pytest
from utils.validators import (
    is_valid_domain,
    is_valid_ip,
    is_valid_target,
    normalize_url,
    extract_domain,
    sanitize_filename,
)


class TestIsValidDomain:
    """Tests for domain name validation."""

    def test_simple_domain(self):
        assert is_valid_domain("example.com") is True

    def test_subdomain(self):
        assert is_valid_domain("sub.example.com") is True

    def test_long_tld(self):
        assert is_valid_domain("example.co.uk") is True

    def test_hyphenated_label(self):
        assert is_valid_domain("my-site.example.com") is True

    def test_single_label_rejected(self):
        assert is_valid_domain("localhost") is False

    def test_leading_hyphen_rejected(self):
        assert is_valid_domain("-invalid.com") is False

    def test_trailing_hyphen_rejected(self):
        assert is_valid_domain("invalid-.com") is False

    def test_empty_string(self):
        assert is_valid_domain("") is False

    def test_too_long(self):
        label = "a" * 64 + ".com"
        assert is_valid_domain(label) is False

    def test_numeric_only_tld_rejected(self):
        assert is_valid_domain("test.123") is False


class TestIsValidIp:
    """Tests for IP address validation."""

    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_ipv4_localhost(self):
        assert is_valid_ip("127.0.0.1") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True

    def test_valid_ipv6_full(self):
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is False

    def test_domain_is_not_ip(self):
        assert is_valid_ip("google.com") is False

    def test_empty_string(self):
        assert is_valid_ip("") is False


class TestIsValidTarget:
    """Tests for combined target validation."""

    def test_domain_accepted(self):
        assert is_valid_target("scanme.nmap.org") is True

    def test_ip_accepted(self):
        assert is_valid_target("8.8.8.8") is True

    def test_garbage_rejected(self):
        assert is_valid_target("not a valid target!") is False


class TestNormalizeUrl:
    """Tests for URL scheme normalization."""

    def test_adds_https(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_preserves_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalize_url("http://example.com") == "http://example.com"


class TestExtractDomain:
    """Tests for domain extraction from URLs."""

    def test_plain_domain(self):
        assert extract_domain("example.com") == "example.com"

    def test_https_url(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_http_with_port(self):
        assert extract_domain("http://example.com:8080/page") == "example.com"

    def test_domain_with_path(self):
        assert extract_domain("example.com/some/path") == "example.com"


class TestSanitizeFilename:
    """Tests for filename sanitization."""

    def test_strips_scheme(self):
        result = sanitize_filename("https://example.com")
        assert "://" not in result

    def test_strips_slashes(self):
        result = sanitize_filename("example.com/path/to/page")
        assert "/" not in result

    def test_plain_domain_unchanged(self):
        assert sanitize_filename("example.com") == "example.com"
