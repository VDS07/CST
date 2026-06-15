"""
DNS Lookup module for CyberShield Toolkit.

Queries a domain for common DNS record types (A, AAAA, MX, NS, TXT,
SOA, CNAME) and returns structured results including TTL values.
Supports an optional custom nameserver override.
"""

import dns.resolver
from typing import Any, Dict, List, Optional
from utils.logger import setup_logger

logger = setup_logger("dns_lookup")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def _create_resolver(nameserver: Optional[str] = None) -> dns.resolver.Resolver:
    """
    Build a resolver instance, optionally pointed at a custom nameserver.

    Args:
        nameserver: IP address of a DNS server to query (e.g. ``8.8.8.8``).

    Returns:
        A configured :class:`dns.resolver.Resolver`.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def _extract_record_value(rtype: str, rdata) -> str:
    """Extract a human-readable value from an rdata object."""
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text()}"
    if rtype == "NS":
        return rdata.target.to_text()
    if rtype == "SOA":
        return (
            f"primary={rdata.mname.to_text()} "
            f"contact={rdata.rname.to_text()} "
            f"serial={rdata.serial}"
        )
    if rtype == "TXT":
        return " ".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
    if rtype == "CNAME":
        return rdata.target.to_text()
    # A / AAAA
    return rdata.address


def run(domain: str, nameserver: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform DNS lookups for all common record types on a domain.

    Args:
        domain: The domain name to query.
        nameserver: Optional custom nameserver IP address.

    Returns:
        A dictionary keyed by record type, where each value is a list
        of dicts containing ``value`` and ``ttl`` fields.
    """
    logger.info(f"Starting DNS lookup for: {domain}")

    results: Dict[str, Any] = {"domain": domain}
    resolver = _create_resolver(nameserver)

    for rtype in RECORD_TYPES:
        results[rtype] = []
        try:
            answers = resolver.resolve(domain, rtype)
            ttl = answers.rrset.ttl
            for rdata in answers:
                results[rtype].append({
                    "value": _extract_record_value(rtype, rdata),
                    "ttl": ttl,
                })
            logger.debug(f"{rtype}: {len(results[rtype])} record(s) found.")
        except dns.resolver.NoAnswer:
            logger.debug(f"{rtype}: No answer.")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist (NXDOMAIN).")
            results["error"] = f"Domain {domain} does not exist."
            break
        except dns.resolver.Timeout:
            logger.debug(f"{rtype}: Query timed out.")
        except Exception as exc:
            logger.debug(f"{rtype}: Lookup failed — {exc}")

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
