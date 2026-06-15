# Changelog

All notable changes to CyberShield Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-06-15

### Added
- **Port Scanner** — Multi-threaded TCP port scanning (1–1024) with configurable range, timeout, and worker count.
- **DNS Lookup** — Retrieves A, AAAA, MX, NS, TXT, SOA, and CNAME records with TTL values.
- **WHOIS Lookup** — Domain registration details including registrar, dates, name servers, and status codes.
- **Security Headers Checker** — Evaluates HTTP endpoints against 8 critical security headers with severity ratings.
- **Subdomain Finder** — Concurrent brute-force discovery with HTTP status checks and response timing.
- **SSL/TLS Analyzer** — Certificate validation, issuer info, expiry checks, SAN enumeration, and TLS version detection.
- **Technology Detector** — Identifies web servers, frameworks, CMS platforms, and programming languages from HTTP responses.
- Interactive CLI menu with `rich` console UI.
- CLI argument mode (`--module`, `--target`) for scripting and automation.
- `--version`, `--verbose`, and `--output-dir` flags.
- Dual-format report generation (JSON + TXT) with timestamped filenames.
- Centralized rotating log system (`logs/cybershield.log`).
- Input validation for domains, IPs, and URLs.
- Unit test suite with `pytest` and mocked network calls.
- Project packaging via `setup.py` with `cybershield` console entry point.

### Infrastructure
- MIT License
- Contributing guidelines (`CONTRIBUTING.md`)
- Security policy (`SECURITY.md`)
- Full `.gitignore` for Python projects
- Linting config (flake8) and formatter config (black) in `setup.cfg`
