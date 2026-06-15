"""
Subdomain Finder module for CyberShield Toolkit.

Performs concurrent DNS brute-force enumeration of common subdomain
prefixes, then optionally probes discovered hosts over HTTP to
collect status codes and response times.
"""

import socket
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from utils.logger import setup_logger

logger = setup_logger("subdomain_finder")

# Expanded default wordlist covering the most common subdomain prefixes
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "store", "secure", "portal", "cdn", "ns1", "ns2",
    "mx", "smtp", "pop", "imap", "webmail", "remote", "vpn", "gateway",
    "intranet", "dashboard", "app", "beta", "demo", "docs", "status",
    "support", "help", "forum", "wiki", "git", "ci", "jenkins", "jira",
    "grafana", "monitor", "analytics", "media", "static", "assets",
    "img", "images", "files", "download", "backup", "db", "database",
]

HTTP_TIMEOUT = 4  # seconds per HTTP probe


def _resolve_subdomain(
    prefix: str, domain: str
) -> Optional[Tuple[str, str]]:
    """
    Try to resolve ``prefix.domain`` to an IP address via DNS.

    Returns:
        A tuple ``(fqdn, ip)`` on success, or ``None`` if unresolvable.
    """
    fqdn = f"{prefix}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None
    except Exception as exc:
        logger.debug(f"Error resolving {fqdn}: {exc}")
        return None


def _probe_http(fqdn: str) -> Tuple[Optional[int], str]:
    """
    Send an HTTP GET to the subdomain and return status + response time.

    Returns:
        A tuple ``(status_code, response_time_str)``.
    """
    try:
        start = time.time()
        resp = requests.get(
            f"http://{fqdn}",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
        elapsed = time.time() - start
        return resp.status_code, f"{elapsed:.2f}s"
    except Exception:
        return None, "—"


def run(
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_workers: int = 20,
    probe_http: bool = True,
) -> Dict[str, Any]:
    """
    Enumerate subdomains for a domain using DNS resolution.

    Each prefix from the wordlist is prepended to the target domain
    and resolved concurrently. Discovered hosts are optionally probed
    via HTTP for a status code and response time measurement.

    Args:
        domain: Base domain to enumerate (e.g. ``example.com``).
        wordlist: Custom list of subdomain prefixes. Falls back to
            the built-in 50-entry default list when not supplied.
        max_workers: Concurrency limit for DNS resolution threads.
        probe_http: Whether to perform HTTP probes on discovered hosts.

    Returns:
        A dictionary with a ``subdomains`` list of discovered entries,
        each containing the FQDN, IP, HTTP status, and response time.
    """
    logger.info(f"Starting subdomain enumeration for: {domain}")

    prefixes = wordlist if wordlist else DEFAULT_WORDLIST

    results: Dict[str, Any] = {
        "domain": domain,
        "wordlist_size": len(prefixes),
        "subdomains": [],
    }

    discovered: List[Tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_subdomain, prefix, domain): prefix
            for prefix in prefixes
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                discovered.append(res)
                logger.debug(f"Found: {res[0]} -> {res[1]}")

    # Sort alphabetically for consistent output
    discovered.sort(key=lambda r: r[0])

    for fqdn, ip in discovered:
        entry: Dict[str, Any] = {
            "subdomain": fqdn,
            "ip": ip,
            "status_code": None,
            "response_time": "—",
        }
        if probe_http:
            status, resp_time = _probe_http(fqdn)
            entry["status_code"] = status
            entry["response_time"] = resp_time

        results["subdomains"].append(entry)

    if not results["subdomains"]:
        logger.info("No subdomains discovered.")
    else:
        logger.info(f"Discovered {len(results['subdomains'])} subdomain(s).")

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("example.com"))
