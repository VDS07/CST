# CyberShield Toolkit 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A professional Python Cyber Security Toolkit equipped with both a sleek interactive Command Line Interface (CLI) and standard command-line arguments. Built for network diagnostics, recon, and security audits.

## ✨ Features

- **Port Scanner**: Rapidly scans TCP ports (1-1024) using ThreadPool concurrency to identify open services.
- **DNS Lookup**: Retrieves essential DNS records (A, MX, NS) for comprehensive domain profiling.
- **WHOIS Lookup**: Extracts domain registration, registrar info, and expiration dates.
- **Security Headers Checker**: Analyzes target HTTP/HTTPS endpoints for critical security headers (HSTS, CSP, X-Frame-Options, X-XSS-Protection).
- **Subdomain Finder**: Conducts concurrent brute-force discovery of common subdomains to map attack surfaces.

## 🚀 Architecture & Quality

- **Structured Reporting**: Exports scan results automatically in both Human-Readable Text (`.txt`) and Machine-Readable JSON (`.json`) formats.
- **Beautiful Console UI**: Leverages `rich` for elegant tables, progress spinners, and colorful outputs.
- **Centralized Logging**: Diagnostic events and errors are seamlessly logged to `logs/cybershield.log` without cluttering the user interface.
- **Typed & Modular**: Built with modern Python type hints (`typing`) and a plug-and-play module architecture.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybershield-toolkit.git
   cd cybershield-toolkit
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Interactive Mode
Run the tool without arguments to launch the sleek interactive menu:
```bash
python main.py
```

### CLI Arguments Mode
Perfect for scripting and automation. Pass the `--module` and `--target` arguments directly:
```bash
# Example: Run a Port Scan
python main.py --module port_scanner --target scanme.nmap.org

# Example: Check Security Headers
python main.py --module header_checker --target https://google.com
```

### Generated Reports
Results are automatically stored in the `reports/` directory:
- `reports/PortScanner_scanme.nmap.org_20231015_120000.txt`
- `reports/PortScanner_scanme.nmap.org_20231015_120000.json`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
