# Testing Documentation

This document describes how to run and verify the CyberShield Toolkit test suite, and documents recent integration test results against live targets.

## Unit Tests

The project uses `pytest` with mocked network calls so tests run fast and without network access.

### Running Tests

```bash
# Full suite
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=modules --cov=utils --cov-report=term-missing

# Single module
pytest tests/test_port_scanner.py -v
```

### Test Structure

| Test File | Module Under Test | What It Covers |
|-----------|-------------------|----------------|
| `test_validators.py` | `utils/validators.py` | Domain/IP validation, URL normalization, filename sanitization |
| `test_port_scanner.py` | `modules/port_scanner.py` | Open/closed port detection, service resolution, result sorting |
| `test_dns_lookup.py` | `modules/dns_lookup.py` | Record extraction, NXDOMAIN handling, TTL parsing |
| `test_header_checker.py` | `modules/header_checker.py` | Present/missing headers, severity, timeouts, URL normalization |
| `test_whois_lookup.py` | `modules/whois_lookup.py` | Date normalization, successful/failed lookups, missing fields |

---

## Integration Test Results

The following integration tests were run against standard public testing targets to validate end-to-end functionality.

### 1. Port Scanner
**Target:** `scanme.nmap.org`
**Command:** `python main.py --module port_scanner --target scanme.nmap.org`

The scanner correctly identified standard open ports within the 1–1024 range and reported scan duration.

### 2. DNS Lookup
**Target:** `example.com`
**Command:** `python main.py --module dns_lookup --target example.com`

Retrieved A, MX, NS, and TXT records with TTL values.

### 3. WHOIS Lookup
**Target:** `example.com`
**Command:** `python main.py --module whois_lookup --target example.com`

Parsed registrar, creation/expiration dates, name servers, and domain status codes.

### 4. Security Headers Checker
**Target:** `example.com`
**Command:** `python main.py --module header_checker --target example.com`

Evaluated 8 security headers with severity ratings (Critical/Warning/Info) and reported actual values for present headers.

### 5. Subdomain Finder
**Target:** `example.com`
**Command:** `python main.py --module subdomain_finder --target example.com`

Discovered common subdomains with DNS resolution, HTTP status codes, and response times.

### 6. SSL/TLS Analyzer
**Target:** `google.com`
**Command:** `python main.py --module ssl_analyzer --target google.com`

Retrieved certificate subject, issuer, validity dates, SAN entries, TLS version, and computed a letter grade.

### 7. Technology Detector
**Target:** `google.com`
**Command:** `python main.py --module tech_detector --target google.com`

Identified web server, frameworks, and analytics technologies from response headers and HTML body patterns.

---

All reports were generated in both `.json` and `.txt` (formatted table) formats in the `reports/` directory. Logs were written to `logs/cybershield.log` without errors.
