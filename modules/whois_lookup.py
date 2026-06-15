"""
WHOIS Lookup module for CyberShield Toolkit.

Retrieves comprehensive domain registration information including
registrar details, registration dates, name servers, status codes,
organization, and country data.
"""

import whois
from typing import Any, Dict, List, Optional, Union
from utils.logger import setup_logger

logger = setup_logger("whois_lookup")


def _normalize_date(value) -> Optional[str]:
    """
    Convert a WHOIS date field into a consistent string format.

    The python-whois library sometimes returns a single datetime, a
    list of datetimes, or a string. This helper normalises all three.
    """
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _normalize_list(value) -> List[str]:
    """Ensure a field that may be a string or list is always a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def run(domain: str) -> Dict[str, Any]:
    """
    Perform a WHOIS lookup for the target domain.

    Extracts registrar, organization, country, creation/updated/expiry
    dates, domain status codes, and authoritative name servers.

    Args:
        domain: The domain name to look up.

    Returns:
        A dictionary with registration details, or an ``error`` key
        if the lookup failed.
    """
    logger.info(f"Starting WHOIS lookup for: {domain}")

    results: Dict[str, Any] = {
        "domain": domain,
        "registrar": None,
        "organization": None,
        "country": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "error": None,
    }

    try:
        data = whois.whois(domain)

        results["registrar"] = data.registrar
        results["organization"] = getattr(data, "org", None)
        results["country"] = getattr(data, "country", None)
        results["creation_date"] = _normalize_date(data.creation_date)
        results["updated_date"] = _normalize_date(getattr(data, "updated_date", None))
        results["expiration_date"] = _normalize_date(data.expiration_date)
        results["name_servers"] = _normalize_list(data.name_servers)
        results["status"] = _normalize_list(data.status)

        logger.debug(f"WHOIS lookup successful for {domain}.")

    except Exception as exc:
        logger.error(f"WHOIS lookup failed: {exc}")
        results["error"] = str(exc)

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
