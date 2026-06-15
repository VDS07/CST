"""
Security Headers Checker module for CyberShield Toolkit.

Evaluates HTTP/HTTPS endpoints against a curated list of security-critical
response headers. Each header is assigned a severity level (Critical,
Warning, or Info) and its actual value is captured when present.
"""

import requests
import urllib3
from typing import Any, Dict, List
from utils.logger import setup_logger
from utils.validators import normalize_url

# Suppress noisy SSL warnings for targets without valid certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger("header_checker")

# Header definitions: (header_name, display_name, severity)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "Critical"),
    ("Content-Security-Policy", "CSP", "Critical"),
    ("X-Frame-Options", "X-Frame-Options", "Critical"),
    ("X-Content-Type-Options", "X-Content-Type-Options", "Warning"),
    ("X-XSS-Protection", "X-XSS-Protection", "Warning"),
    ("Referrer-Policy", "Referrer-Policy", "Warning"),
    ("Permissions-Policy", "Permissions-Policy", "Info"),
    ("Cross-Origin-Opener-Policy", "COOP", "Info"),
]

REQUEST_TIMEOUT = 10  # seconds


def run(target: str) -> Dict[str, Any]:
    """
    Check a target URL for the presence of security-critical HTTP headers.

    The function sends a GET request to the target (following redirects)
    and inspects the response headers against a predefined checklist.
    Each header is reported with its presence status, severity level,
    and actual value when present.

    Args:
        target: Domain name or full URL to analyse.

    Returns:
        A dictionary containing a list of header analysis results,
        or an ``error`` key if the request failed.
    """
    target_url = normalize_url(target)
    logger.info(f"Checking security headers for: {target_url}")

    results: Dict[str, Any] = {
        "target": target_url,
        "headers": [],
        "score": 0,
        "max_score": len(SECURITY_HEADERS),
        "error": None,
    }

    try:
        response = requests.get(
            target_url,
            verify=False,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        resp_headers = response.headers

        found_count = 0
        for header_key, display_name, severity in SECURITY_HEADERS:
            present = header_key in resp_headers
            entry = {
                "header": display_name,
                "present": present,
                "severity": severity,
                "value": resp_headers.get(header_key, "") if present else "",
            }
            results["headers"].append(entry)
            if present:
                found_count += 1

        results["score"] = found_count
        logger.debug(
            f"Headers checked: {found_count}/{len(SECURITY_HEADERS)} present."
        )

    except requests.ConnectionError as exc:
        logger.error(f"Connection failed: {exc}")
        results["error"] = f"Connection failed: {exc}"
    except requests.Timeout:
        logger.error("Request timed out.")
        results["error"] = "Request timed out."
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        results["error"] = str(exc)

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
