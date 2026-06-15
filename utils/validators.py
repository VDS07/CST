"""
Input validation utilities for CyberShield Toolkit.

Provides domain, IP address, and URL validation functions used
across all scanner modules to sanitize user input before processing.
"""

import re
import socket
from typing import Optional
from urllib.parse import urlparse


# RFC 1123 compliant domain pattern
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain name against RFC 1123 rules.

    Args:
        domain: The domain string to validate.

    Returns:
        True if the domain is syntactically valid, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_PATTERN.match(domain))


def is_valid_ip(address: str) -> bool:
    """
    Check whether a string is a valid IPv4 or IPv6 address.

    Args:
        address: The IP address string to validate.

    Returns:
        True if the address is a valid IPv4 or IPv6 address.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, address)
            return True
        except (socket.error, OSError):
            continue
    return False


def is_valid_target(target: str) -> bool:
    """
    Check if a target is either a valid domain or a valid IP address.

    Args:
        target: Domain name or IP address string.

    Returns:
        True if the target is usable for scanning.
    """
    return is_valid_domain(target) or is_valid_ip(target)


def normalize_url(target: str) -> str:
    """
    Ensure a target has an HTTPS scheme prefix.

    If the target already starts with ``http://`` or ``https://``,
    it is returned unchanged. Otherwise ``https://`` is prepended.

    Args:
        target: Raw target string from user input.

    Returns:
        The target with a guaranteed URL scheme.
    """
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def extract_domain(target: str) -> str:
    """
    Extract the bare domain/host from a URL or return the target as-is.

    Strips scheme, port, and path components so that modules
    expecting a plain hostname receive clean input.

    Args:
        target: URL or domain string.

    Returns:
        The hostname portion of the input.
    """
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # Strip trailing slashes or paths
    return target.split("/")[0].split(":")[0]


def sanitize_filename(target: str) -> str:
    """
    Convert a target string into a safe filename component.

    Replaces ``://``, ``/``, ``:``, and other problematic characters
    with underscores.

    Args:
        target: The raw target string.

    Returns:
        A filesystem-safe version of the target.
    """
    unsafe = ["://", "/", ":", "*", "?", '"', "<", ">", "|"]
    result = target
    for char in unsafe:
        result = result.replace(char, "_")
    return result
