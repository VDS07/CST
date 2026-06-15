"""
CyberShield Toolkit — main entry point.

A modular Python toolkit for network reconnaissance and security
auditing. Supports both an interactive CLI menu and direct
command-line arguments for scripted automation.

Usage:
    Interactive mode:  python main.py
    CLI mode:          python main.py --module port_scanner --target scanme.nmap.org
    With options:      python main.py --module port_scanner --target 10.0.0.1 --verbose --output-dir ./results
"""

import os
import sys
import json
import datetime
import argparse
from typing import Dict, Any

from rich.prompt import Prompt

from utils.formatter import (
    console,
    print_banner,
    print_success,
    print_error,
    print_warning,
    print_info,
    print_section,
    create_table,
    render_text_report,
    __version__,
)
from utils.logger import setup_logger
from utils.validators import is_valid_target, sanitize_filename, extract_domain
from modules import (
    port_scanner,
    dns_lookup,
    whois_lookup,
    header_checker,
    subdomain_finder,
    ssl_analyzer,
    tech_detector,
)

__author__ = "VDS07"

logger = setup_logger("main")

# Module registry: maps CLI name -> (display_name, runner, needs_domain)
MODULE_REGISTRY = {
    "port_scanner":     ("PortScanner",     "Port Scanner",              True),
    "dns_lookup":       ("DNSLookup",       "DNS Lookup",                True),
    "whois_lookup":     ("WHOISLookup",     "WHOIS Lookup",              True),
    "header_checker":   ("HeaderChecker",   "Security Headers Checker",  False),
    "subdomain_finder": ("SubdomainFinder", "Subdomain Finder",          True),
    "ssl_analyzer":     ("SSLAnalyzer",     "SSL/TLS Analyzer",          True),
    "tech_detector":    ("TechDetector",    "Technology Detector",       False),
}


# ── Report persistence ──────────────────────────────────────────────

def save_report(
    module_name: str,
    target: str,
    results: Dict[str, Any],
    output_dir: str = "reports",
):
    """
    Persist scan results to disk in both JSON and human-readable text.

    The text report uses formatted tables produced by
    :func:`utils.formatter.render_text_report` instead of raw JSON.

    Args:
        module_name: Internal module name (e.g. ``PortScanner``).
        target: The scanned target.
        results: Results dictionary from the module's ``run()`` call.
        output_dir: Directory to write reports into.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = sanitize_filename(target)
    base = os.path.join(output_dir, f"{module_name}_{safe_target}_{timestamp}")

    # JSON (machine-readable)
    json_path = f"{base}.json"
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=4, default=str)
        logger.debug(f"JSON report saved: {json_path}")
    except OSError as exc:
        logger.error(f"Failed to save JSON report: {exc}")

    # TXT (human-readable, formatted tables)
    txt_path = f"{base}.txt"
    try:
        report_text = render_text_report(module_name, target, results)
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        logger.debug(f"Text report saved: {txt_path}")
        print_success(
            f"Reports saved to [bold cyan]{json_path}[/bold cyan] "
            f"and [bold cyan]{txt_path}[/bold cyan]"
        )
    except OSError as exc:
        logger.error(f"Failed to save text report: {exc}")
        print_error(f"Could not save report: {exc}")


# ── Module runners (console display) ────────────────────────────────

def run_port_scanner(target: str, output_dir: str = "reports"):
    """Execute port scan and display results."""
    with console.status(f"[bold green]Scanning ports on {target}...", spinner="dots"):
        results = port_scanner.run(target)

    if results.get("open_ports"):
        table = create_table("Open Ports", ["Port", "Status", "Service"])
        for p in results["open_ports"]:
            table.add_row(
                str(p["port"]),
                f"[green]{p['status']}[/green]",
                p["service"],
            )
        console.print(table)
        print_info(
            f"Scan completed in {results.get('scan_duration_seconds', '?')}s "
            f"| Range: {results.get('ports_scanned', 'N/A')}"
        )
    else:
        print_info("No open ports found in the scanned range.")

    save_report("PortScanner", target, results, output_dir)


def run_dns_lookup(target: str, output_dir: str = "reports"):
    """Execute DNS lookup and display results."""
    with console.status(f"[bold green]Querying DNS records for {target}...", spinner="dots"):
        results = dns_lookup.run(target)

    table = create_table("DNS Records", ["Type", "Value", "TTL"])
    row_count = 0
    for rtype in dns_lookup.RECORD_TYPES:
        for record in results.get(rtype, []):
            if isinstance(record, dict):
                table.add_row(rtype, record["value"], str(record.get("ttl", "")))
            else:
                table.add_row(rtype, str(record), "")
            row_count += 1

    if row_count > 0:
        console.print(table)
    else:
        print_info("No DNS records found.")

    save_report("DNSLookup", target, results, output_dir)


def run_whois_lookup(target: str, output_dir: str = "reports"):
    """Execute WHOIS lookup and display results."""
    with console.status(f"[bold green]WHOIS lookup for {target}...", spinner="dots"):
        results = whois_lookup.run(target)

    if results.get("error"):
        print_error(results["error"])
    else:
        table = create_table("WHOIS Information", ["Property", "Value"])
        fields = [
            ("Registrar", "registrar"),
            ("Organization", "organization"),
            ("Country", "country"),
            ("Creation Date", "creation_date"),
            ("Updated Date", "updated_date"),
            ("Expiration Date", "expiration_date"),
        ]
        for label, key in fields:
            value = results.get(key)
            table.add_row(label, str(value) if value else "N/A")

        ns_list = results.get("name_servers", [])
        if ns_list:
            table.add_row("Name Servers", ", ".join(ns_list[:5]))

        status_list = results.get("status", [])
        if status_list:
            table.add_row("Status", ", ".join(s.split()[0] for s in status_list[:3]))

        console.print(table)

    save_report("WHOISLookup", target, results, output_dir)


def run_header_checker(target: str, output_dir: str = "reports"):
    """Execute security headers check and display results."""
    with console.status(f"[bold green]Checking security headers for {target}...", spinner="dots"):
        results = header_checker.run(target)

    if results.get("error"):
        print_error(results["error"])
    else:
        table = create_table("Security Headers Analysis", ["Header", "Status", "Severity"])
        for h in results.get("headers", []):
            if h["present"]:
                status_str = "[bold green]✓ Present[/bold green]"
            else:
                status_str = "[bold red]✗ Missing[/bold red]"

            severity = h.get("severity", "")
            if severity == "Critical":
                sev_str = f"[bold red]{severity}[/bold red]"
            elif severity == "Warning":
                sev_str = f"[bold yellow]{severity}[/bold yellow]"
            else:
                sev_str = f"[dim]{severity}[/dim]"

            table.add_row(h["header"], status_str, sev_str)

        console.print(table)
        score = results.get("score", 0)
        total = results.get("max_score", 0)
        print_info(f"Score: {score}/{total} headers present")

    save_report("HeaderChecker", target, results, output_dir)


def run_subdomain_finder(target: str, output_dir: str = "reports"):
    """Execute subdomain enumeration and display results."""
    with console.status(f"[bold green]Enumerating subdomains for {target}...", spinner="dots"):
        results = subdomain_finder.run(target)

    subs = results.get("subdomains", [])
    if subs:
        table = create_table(
            "Discovered Subdomains",
            ["Subdomain", "IP Address", "HTTP Status", "Response Time"],
        )
        for s in subs:
            status = str(s.get("status_code", "—")) if s.get("status_code") else "—"
            table.add_row(
                s["subdomain"],
                s["ip"],
                status,
                s.get("response_time", "—"),
            )
        console.print(table)
    else:
        print_info("No subdomains discovered.")

    save_report("SubdomainFinder", target, results, output_dir)


def run_ssl_analyzer(target: str, output_dir: str = "reports"):
    """Execute SSL/TLS analysis and display results."""
    with console.status(f"[bold green]Analyzing SSL/TLS for {target}...", spinner="dots"):
        results = ssl_analyzer.run(target)

    if results.get("error"):
        print_error(results["error"])
    else:
        cert = results.get("certificate", {})
        table = create_table("SSL/TLS Certificate", ["Property", "Value"])
        table.add_row("Subject", cert.get("subject", "N/A"))
        table.add_row("Issuer", cert.get("issuer", "N/A"))
        table.add_row("Valid From", cert.get("valid_from", "N/A"))
        table.add_row("Valid Until", cert.get("valid_until", "N/A"))
        table.add_row("Days Remaining", str(cert.get("days_remaining", "N/A")))
        table.add_row("TLS Version", results.get("tls_version", "N/A"))
        table.add_row("SANs", str(cert.get("san_count", 0)))

        grade = results.get("grade", "?")
        grade_colors = {"A": "green", "B": "yellow", "C": "red", "F": "bold red"}
        color = grade_colors.get(grade, "white")
        table.add_row("Grade", f"[{color}]{grade}[/{color}]")

        console.print(table)

        # Show SANs if present
        sans = cert.get("san", [])
        if sans:
            san_table = create_table("Subject Alternative Names", ["SAN Entry"])
            for san in sans[:15]:  # Limit display to 15
                san_table.add_row(san)
            if len(sans) > 15:
                san_table.add_row(f"... and {len(sans) - 15} more")
            console.print(san_table)

    save_report("SSLAnalyzer", target, results, output_dir)


def run_tech_detector(target: str, output_dir: str = "reports"):
    """Execute technology detection and display results."""
    with console.status(f"[bold green]Detecting technologies on {target}...", spinner="dots"):
        results = tech_detector.run(target)

    if results.get("error"):
        print_error(results["error"])
    else:
        techs = results.get("technologies", [])
        if techs:
            table = create_table("Detected Technologies", ["Technology", "Category", "Evidence"])
            for t in techs:
                table.add_row(t["name"], t["category"], t.get("detail", ""))
            console.print(table)
        else:
            print_info("No technologies detected.")

        server = results.get("server_info", {})
        if server:
            info_table = create_table("Server Information", ["Property", "Value"])
            for key, val in server.items():
                info_table.add_row(key, val)
            console.print(info_table)

    save_report("TechDetector", target, results, output_dir)


# ── Interactive menu ────────────────────────────────────────────────

MENU_OPTIONS = [
    ("1", "Port Scanner",              run_port_scanner),
    ("2", "DNS Lookup",                run_dns_lookup),
    ("3", "WHOIS Lookup",              run_whois_lookup),
    ("4", "Security Headers Checker",  run_header_checker),
    ("5", "Subdomain Finder",          run_subdomain_finder),
    ("6", "SSL/TLS Analyzer",          run_ssl_analyzer),
    ("7", "Technology Detector",       run_tech_detector),
    ("0", "Exit",                      None),
]


def interactive_menu(output_dir: str = "reports"):
    """Run the interactive menu loop."""
    while True:
        print_banner()
        console.print()
        for key, label, _ in MENU_OPTIONS:
            if key == "0":
                console.print(f"  [bold red][{key}][/bold red] {label}")
            else:
                console.print(f"  [bold yellow][{key}][/bold yellow] {label}")
        console.print()

        choice = Prompt.ask(
            "[bold cyan]Select an option[/bold cyan]",
            choices=[opt[0] for opt in MENU_OPTIONS],
        )

        if choice == "0":
            print_info("Exiting CyberShield Toolkit. Stay safe!")
            break

        # Find and execute the selected runner
        for key, label, runner in MENU_OPTIONS:
            if key == choice and runner:
                print_section(label)
                target = Prompt.ask("  Enter target (domain / IP / URL)")
                if not target.strip():
                    print_warning("No target provided. Returning to menu.")
                    break
                target = target.strip()
                domain = extract_domain(target)
                if not is_valid_target(domain) and not target.startswith("http"):
                    print_warning(
                        f"'{target}' doesn't look like a valid domain or IP. "
                        "Proceeding anyway..."
                    )
                runner(target, output_dir)
                break

        console.print()


# ── CLI argument parsing ────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="cybershield",
        description="CyberShield Toolkit — Network Reconnaissance & Security Auditing",
        epilog="Example: python main.py --module port_scanner --target scanme.nmap.org",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"CyberShield Toolkit v{__version__}",
    )
    parser.add_argument(
        "--module", "-m",
        choices=list(MODULE_REGISTRY.keys()),
        help="Scanner module to execute.",
    )
    parser.add_argument(
        "--target", "-t",
        help="Target domain, IP address, or URL.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Directory for report output (default: reports/).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) console logging.",
    )
    return parser.parse_args()


# ── Module dispatcher ───────────────────────────────────────────────

RUNNERS = {
    "port_scanner":     run_port_scanner,
    "dns_lookup":       run_dns_lookup,
    "whois_lookup":     run_whois_lookup,
    "header_checker":   run_header_checker,
    "subdomain_finder": run_subdomain_finder,
    "ssl_analyzer":     run_ssl_analyzer,
    "tech_detector":    run_tech_detector,
}


def main():
    """Application entry point."""
    args = parse_args()

    # Re-initialize loggers with verbose flag if requested
    if args.verbose:
        setup_logger("main", verbose=True)

    if args.module and args.target:
        logger.info(f"CLI mode: module={args.module}, target={args.target}")
        print_banner()
        runner = RUNNERS.get(args.module)
        if runner:
            runner(args.target, args.output_dir)
        else:
            print_error(f"Unknown module: {args.module}")
            sys.exit(1)

    elif args.module or args.target:
        print_error("Both --module and --target are required for CLI mode.")
        sys.exit(2)

    else:
        logger.info("Launching interactive menu.")
        try:
            interactive_menu(args.output_dir)
        except KeyboardInterrupt:
            console.print()
            print_info("Interrupted. Exiting gracefully.")
            sys.exit(0)


if __name__ == "__main__":
    main()
