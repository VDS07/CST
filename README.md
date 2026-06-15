# CyberShield Toolkit 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A modular Python toolkit for network reconnaissance and security auditing. Comes with an interactive CLI menu and scriptable command-line arguments — built for pentesters, students, and anyone interested in practical cybersecurity.

---

## Features

| Module | Description |
|--------|-------------|
| **Port Scanner** | Multi-threaded TCP connect scan (configurable range, timeout, workers) |
| **DNS Lookup** | Retrieves A, AAAA, MX, NS, TXT, SOA, CNAME records with TTL values |
| **WHOIS Lookup** | Domain registration details — registrar, dates, name servers, status |
| **Security Headers** | Evaluates 8 critical HTTP security headers with severity ratings |
| **Subdomain Finder** | Concurrent brute-force enumeration with HTTP probing and timing |
| **SSL/TLS Analyzer** | Certificate validation, SAN extraction, TLS version, A–F grading |
| **Tech Detector** | Identifies servers, frameworks, CMS, languages from headers & HTML |

## Architecture

```
CST/
├── main.py                 # Entry point (interactive + CLI)
├── modules/
│   ├── port_scanner.py     # TCP port scanning engine
│   ├── dns_lookup.py       # DNS record resolution
│   ├── whois_lookup.py     # WHOIS data retrieval
│   ├── header_checker.py   # HTTP security header analysis
│   ├── subdomain_finder.py # Subdomain enumeration
│   ├── ssl_analyzer.py     # SSL/TLS certificate analysis
│   └── tech_detector.py    # Web technology fingerprinting
├── utils/
│   ├── formatter.py        # Rich console UI + report renderer
│   ├── logger.py           # Rotating file logger
│   └── validators.py       # Input validation (domain, IP, URL)
├── tests/                  # pytest unit tests with mocks
├── reports/                # Auto-generated scan reports (git-ignored)
├── logs/                   # Application logs (git-ignored)
├── setup.py                # Package configuration
├── setup.cfg               # Linter + pytest config
├── requirements.txt        # Production dependencies
└── requirements-dev.txt    # Development/testing dependencies
```

### Design Decisions

- **Modular plugin pattern** — every scanner is a standalone module exposing `run(target) -> dict`. Adding a new scanner means creating one file and registering it in `main.py`.
- **Dual-format reports** — each scan produces both a machine-readable JSON and a human-readable formatted text report with tables.
- **Rich console UI** — colour-coded tables, spinners, and severity indicators via the `rich` library.
- **Rotating log system** — debug logs go to file (5MB rotation, 3 backups), only warnings surface to console.
- **Input validation** — all targets are validated before scanning (RFC 1123 domains, IPv4/IPv6).
- **Thread-pooled I/O** — port scanning and subdomain enumeration use `ThreadPoolExecutor` for concurrency.

## Installation

```bash
git clone https://github.com/VDS07/CST.git
cd CST
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
```

For development (includes pytest, flake8, black):
```bash
pip install -r requirements-dev.txt
```

## Usage

### Interactive Mode

Launch the menu-driven interface:
```bash
python main.py
```

### CLI Mode

Run any module directly — useful for scripting and automation:
```bash
# Port scan
python main.py --module port_scanner --target scanme.nmap.org

# DNS lookup
python main.py --module dns_lookup --target google.com

# WHOIS
python main.py --module whois_lookup --target github.com

# Security headers check
python main.py --module header_checker --target https://example.com

# Subdomain enumeration
python main.py --module subdomain_finder --target example.com

# SSL/TLS analysis
python main.py --module ssl_analyzer --target github.com

# Technology detection
python main.py --module tech_detector --target google.com
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--module`, `-m` | Scanner module to run |
| `--target`, `-t` | Target domain, IP, or URL |
| `--output-dir`, `-o` | Report output directory (default: `reports/`) |
| `--verbose`, `-v` | Enable debug-level console output |
| `--version`, `-V` | Print version and exit |

### Generated Reports

Reports are automatically saved in the `reports/` directory:
```
reports/
├── PortScanner_scanme.nmap.org_20260615_143000.json
├── PortScanner_scanme.nmap.org_20260615_143000.txt
├── SSLAnalyzer_github.com_20260615_143200.json
└── SSLAnalyzer_github.com_20260615_143200.txt
```

The `.txt` reports use formatted tables:
```
+------------------------------------------------------------------------------+
|                     CYBERSHIELD TOOLKIT — SCAN REPORT                        |
+------------------------------------------------------------------------------+
| Module                              | PortScanner                            |
| Target                              | scanme.nmap.org                        |
| Date                                | 2026-06-15 14:30:00                    |
+------------------------------------------------------------------------------+

  OPEN PORTS
  +------------------------+------------------------+----------------------------+
  | Port                   | Status                 | Service                    |
  +------------------------+------------------------+----------------------------+
  | 22                     | OPEN                   | SSH                        |
  | 80                     | OPEN                   | HTTP                       |
  +------------------------+------------------------+----------------------------+

  Scan completed in 12.34 seconds.
  Ports scanned: 1-1024
```

## Testing

Run the full test suite:
```bash
pytest tests/ -v
```

With coverage:
```bash
pytest tests/ -v --cov=modules --cov=utils --cov-report=term-missing
```

## Roadmap

- [ ] Nmap-style service version detection via banner grabbing
- [ ] CSV/HTML report export formats
- [ ] Custom subdomain wordlist loading from file
- [ ] Configuration file support (YAML/TOML)
- [ ] Plugin system for community-contributed modules
- [ ] Async I/O migration (asyncio + aiohttp)

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Always ensure you have written permission before scanning any network or system. See [SECURITY.md](SECURITY.md) for the full responsible use policy.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
