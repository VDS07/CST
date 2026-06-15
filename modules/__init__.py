"""
Scanner modules for CyberShield Toolkit.

Each module exposes a ``run(target) -> dict`` interface that performs
a specific reconnaissance or security audit task and returns structured
results suitable for both console display and report generation.
"""

__all__ = [
    "port_scanner",
    "dns_lookup",
    "whois_lookup",
    "header_checker",
    "subdomain_finder",
    "ssl_analyzer",
    "tech_detector",
]
