"""
SSL/TLS Analyzer module for CyberShield Toolkit.

Connects to a target host over TLS, retrieves the X.509 certificate,
and evaluates its validity, issuer chain, expiration, Subject
Alternative Names (SANs), and negotiated TLS protocol version.
Assigns a simple letter grade (A–F) based on the findings.
"""

import ssl
import socket
import datetime
from typing import Any, Dict, List
from utils.logger import setup_logger
from utils.validators import extract_domain

logger = setup_logger("ssl_analyzer")

DEFAULT_PORT = 443
CONNECT_TIMEOUT = 10  # seconds


def _parse_subject_field(cert_dict: dict, field: str) -> str:
    """Extract a single field value from the certificate subject tuple."""
    subject = cert_dict.get("subject", ())
    for entry in subject:
        for key, value in entry:
            if key == field:
                return value
    return ""


def _parse_issuer(cert_dict: dict) -> str:
    """Build a readable issuer string from the certificate issuer tuple."""
    issuer = cert_dict.get("issuer", ())
    parts = []
    for entry in issuer:
        for key, value in entry:
            if key in ("organizationName", "commonName"):
                parts.append(value)
    return " / ".join(parts) if parts else "Unknown"


def _extract_sans(cert_dict: dict) -> List[str]:
    """Pull all Subject Alternative Names from the certificate."""
    san_entries = cert_dict.get("subjectAltName", ())
    return [value for _type, value in san_entries]


def _compute_grade(
    days_remaining: int,
    tls_version: str,
    has_san: bool,
) -> str:
    """
    Assign a letter grade based on certificate and TLS health.

    Grading logic:
        A — Valid cert, TLSv1.2+, >30 days remaining, SANs present
        B — Valid cert, TLSv1.2+, 7–30 days remaining
        C — Valid cert, older TLS or <7 days remaining
        F — Expired certificate or connection failure
    """
    if days_remaining <= 0:
        return "F"
    if tls_version in ("TLSv1.3", "TLSv1.2") and days_remaining > 30 and has_san:
        return "A"
    if tls_version in ("TLSv1.3", "TLSv1.2") and days_remaining > 7:
        return "B"
    return "C"


def run(target: str, port: int = DEFAULT_PORT) -> Dict[str, Any]:
    """
    Analyze the SSL/TLS certificate and connection of a target host.

    Establishes a TLS connection, retrieves the peer certificate,
    and evaluates validity dates, issuer, SANs, and TLS version.

    Args:
        target: Domain name or URL to analyse.
        port: TCP port to connect on (default 443).

    Returns:
        A dictionary with certificate details, TLS version,
        and a computed grade. Contains an ``error`` key on failure.
    """
    hostname = extract_domain(target)
    logger.info(f"Starting SSL/TLS analysis for: {hostname}:{port}")

    results: Dict[str, Any] = {
        "target": hostname,
        "port": port,
        "certificate": {},
        "tls_version": None,
        "grade": "F",
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = tls_sock.version() or "Unknown"

                if not cert:
                    results["error"] = "No certificate returned by server."
                    return results

                # Parse dates
                not_before = ssl.cert_time_to_seconds(cert["notBefore"])
                not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                valid_from = datetime.datetime.utcfromtimestamp(not_before)
                valid_until = datetime.datetime.utcfromtimestamp(not_after)
                days_remaining = (valid_until - datetime.datetime.utcnow()).days

                sans = _extract_sans(cert)

                results["certificate"] = {
                    "subject": _parse_subject_field(cert, "commonName"),
                    "issuer": _parse_issuer(cert),
                    "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
                    "valid_until": valid_until.strftime("%Y-%m-%d %H:%M:%S"),
                    "days_remaining": days_remaining,
                    "serial_number": cert.get("serialNumber", ""),
                    "signature_algorithm": cert.get("signatureAlgorithm", "N/A"),
                    "san": sans,
                    "san_count": len(sans),
                }
                results["tls_version"] = tls_version
                results["grade"] = _compute_grade(days_remaining, tls_version, len(sans) > 0)

                logger.debug(
                    f"Certificate valid until {valid_until.date()} "
                    f"({days_remaining} days). TLS: {tls_version}. "
                    f"Grade: {results['grade']}"
                )

    except ssl.SSLCertVerificationError as exc:
        logger.error(f"Certificate verification failed: {exc}")
        results["error"] = f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        logger.error(f"SSL error: {exc}")
        results["error"] = f"SSL error: {exc}"
    except socket.timeout:
        logger.error("Connection timed out.")
        results["error"] = "Connection timed out."
    except OSError as exc:
        logger.error(f"Connection error: {exc}")
        results["error"] = f"Connection error: {exc}"

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
