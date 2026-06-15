"""
Technology Detector module for CyberShield Toolkit.

Identifies web technologies (servers, frameworks, CMS platforms,
programming languages, CDNs) by inspecting HTTP response headers,
cookies, and HTML content patterns.
"""

import re
import requests
import urllib3
from typing import Any, Dict, List
from utils.logger import setup_logger
from utils.validators import normalize_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger("tech_detector")

REQUEST_TIMEOUT = 10

# Signature definitions: (pattern, technology_name, category)
# Patterns are checked against the full response body (case-insensitive).
HTML_SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress", "CMS"),
    (r"Joomla!", "Joomla", "CMS"),
    (r"Drupal\.settings", "Drupal", "CMS"),
    (r"Shopify\.theme", "Shopify", "E-commerce"),
    (r"<meta[^>]+generator[^>]+Hugo", "Hugo", "Static Site Generator"),
    (r"<meta[^>]+generator[^>]+Jekyll", "Jekyll", "Static Site Generator"),
    (r"<meta[^>]+generator[^>]+Next\.js", "Next.js", "Framework"),
    (r"__next", "Next.js", "Framework"),
    (r"__nuxt", "Nuxt.js", "Framework"),
    (r'ng-version="|ng-app', "Angular", "Framework"),
    (r"react-root|_reactRootContainer|__REACT", "React", "Framework"),
    (r"vue-app|__vue|Vue\.js", "Vue.js", "Framework"),
    (r"jquery|jQuery", "jQuery", "JavaScript Library"),
    (r"bootstrap\.min\.css|bootstrap\.min\.js", "Bootstrap", "CSS Framework"),
    (r"tailwindcss|tailwind\.css", "Tailwind CSS", "CSS Framework"),
    (r"google-analytics\.com|gtag\(", "Google Analytics", "Analytics"),
    (r"googletagmanager\.com", "Google Tag Manager", "Analytics"),
    (r"cloudflare", "Cloudflare", "CDN / Security"),
    (r"recaptcha", "reCAPTCHA", "Security"),
]

# Header-based detection rules: (header_name, pattern, tech_name, category)
HEADER_SIGNATURES = [
    ("Server", r"nginx", "Nginx", "Web Server"),
    ("Server", r"Apache", "Apache", "Web Server"),
    ("Server", r"Microsoft-IIS", "Microsoft IIS", "Web Server"),
    ("Server", r"LiteSpeed", "LiteSpeed", "Web Server"),
    ("Server", r"cloudflare", "Cloudflare", "CDN / Security"),
    ("Server", r"gunicorn", "Gunicorn", "App Server"),
    ("X-Powered-By", r"PHP", "PHP", "Language"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET", "Framework"),
    ("X-Powered-By", r"Express", "Express.js", "Framework"),
    ("X-Powered-By", r"Next\.js", "Next.js", "Framework"),
    ("X-Generator", r"Drupal", "Drupal", "CMS"),
    ("X-Generator", r"WordPress", "WordPress", "CMS"),
    ("Via", r"varnish", "Varnish", "Cache"),
    ("X-Cache", r".", "CDN Cache Layer", "CDN"),
    ("X-Drupal-Cache", r".", "Drupal", "CMS"),
]

# Cookie-based detection
COOKIE_SIGNATURES = [
    ("PHPSESSID", "PHP", "Language"),
    ("JSESSIONID", "Java / Jakarta EE", "Language"),
    ("ASP.NET_SessionId", "ASP.NET", "Framework"),
    ("csrftoken", "Django", "Framework"),
    ("laravel_session", "Laravel", "Framework"),
    ("_rails_session", "Ruby on Rails", "Framework"),
]


def run(target: str) -> Dict[str, Any]:
    """
    Detect web technologies used by the target site.

    Sends an HTTP GET request and inspects response headers, cookies,
    and HTML body for known signatures of web servers, frameworks,
    CMS platforms, programming languages, and CDNs.

    Args:
        target: Domain name or URL to analyse.

    Returns:
        A dictionary containing a deduplicated list of detected
        technologies (each with name, category, and detail) and
        basic server information.
    """
    target_url = normalize_url(target)
    logger.info(f"Starting technology detection for: {target_url}")

    results: Dict[str, Any] = {
        "target": target_url,
        "technologies": [],
        "server_info": {},
        "error": None,
    }

    try:
        response = requests.get(
            target_url,
            verify=False,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberShield-Toolkit/1.0"},
        )
        headers = response.headers
        body = response.text
        cookies = response.cookies

        seen: set = set()

        def _add(name: str, category: str, detail: str = ""):
            if name not in seen:
                seen.add(name)
                results["technologies"].append({
                    "name": name,
                    "category": category,
                    "detail": detail,
                })

        # Server info extraction
        results["server_info"] = {
            "Status Code": str(response.status_code),
            "Content-Type": headers.get("Content-Type", "N/A"),
            "Server": headers.get("Server", "Not disclosed"),
            "X-Powered-By": headers.get("X-Powered-By", "Not disclosed"),
        }

        # Header-based detection
        for header_name, pattern, tech_name, category in HEADER_SIGNATURES:
            value = headers.get(header_name, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                _add(tech_name, category, f"Header: {header_name}: {value[:60]}")

        # Cookie-based detection
        cookie_dict = requests.utils.dict_from_cookiejar(cookies)
        for cookie_name, tech_name, category in COOKIE_SIGNATURES:
            if cookie_name in cookie_dict:
                _add(tech_name, category, f"Cookie: {cookie_name}")

        # HTML body signature detection
        for pattern, tech_name, category in HTML_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                _add(tech_name, category, "HTML body pattern match")

        logger.debug(f"Detected {len(results['technologies'])} technology/ies.")

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
