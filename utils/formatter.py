"""
Console formatting and report generation for CyberShield Toolkit.

Provides rich console helpers for the interactive UI, and a
human-readable text report renderer that outputs clean, tabular
reports instead of raw JSON.
"""

import datetime
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

__version__ = "1.0.0"

console = Console()


# -- Console output helpers ---------------------------------------------------

def print_banner():
    """Display the application banner with version info."""
    banner_art = r"""
   ______      __              _____ __    _      __    __
  / ____/_  __/ /_  ___  _____/ ___// /_  (_)__  / /___/ /
 / /   / / / / __ \/ _ \/ ___/\__ \/ __ \/ / _ \/ / __  / 
/ /___/ /_/ / /_/ /  __/ /   ___/ / / / / /  __/ / /_/ /  
\____/\__, /_.___/\___/_/   /____/_/ /_/_/\___/_/\__,_/   
     /____/                                                
"""
    console.print(banner_art, style="bold cyan")
    console.print(
        f"  [dim]CyberShield Toolkit v{__version__} - Network Recon & Security Audit[/dim]"
    )
    console.print("=" * 60, style="bold cyan")


def print_success(message: str):
    """Print a success message with a green prefix."""
    console.print(f"[bold green][+][/bold green] {message}")


def print_error(message: str):
    """Print an error message with a red prefix."""
    console.print(f"[bold red][-][/bold red] {message}")


def print_warning(message: str):
    """Print a warning message with a yellow prefix."""
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def print_info(message: str):
    """Print an informational message with a blue prefix."""
    console.print(f"[bold blue][*][/bold blue] {message}")


def print_section(title: str):
    """Print a visual section divider."""
    console.print()
    console.print(f"--- {title} ", style="bold cyan", end="")
    console.print("-" * max(1, 55 - len(title)), style="dim cyan")


def create_table(title: str, columns: List[str]) -> Table:
    """
    Build a styled rich Table with the given title and column headers.

    Args:
        title: Table heading shown above the data.
        columns: List of column header labels.

    Returns:
        An empty :class:`rich.table.Table` ready for rows.
    """
    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        title_style="bold white",
        show_lines=True,
    )
    for col in columns:
        table.add_column(col, overflow="fold")
    return table


# -- Human-readable text report renderer --------------------------------------

_SEPARATOR = "+" + "-" * 78 + "+"
_HEADER_LINE = "|{:^78s}|"
_ROW_FORMAT = "| {:<35s} | {:<38s} |"
_ROW_SEPARATOR = "+" + "-" * 37 + "+" + "-" * 40 + "+"


def _render_header(module_name: str, target: str) -> List[str]:
    """Build the report header block."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        _SEPARATOR,
        _HEADER_LINE.format("CYBERSHIELD TOOLKIT - SCAN REPORT"),
        _SEPARATOR,
        _ROW_FORMAT.format("Module", module_name),
        _ROW_FORMAT.format("Target", target),
        _ROW_FORMAT.format("Date", now),
        _SEPARATOR,
        "",
    ]
    return lines


def _render_kv_table(title: str, rows: List[tuple]) -> List[str]:
    """Render a two-column key/value table."""
    lines = [
        f"  {title}",
        "  " + _ROW_SEPARATOR,
        "  " + _ROW_FORMAT.format("Field", "Value"),
        "  " + _ROW_SEPARATOR,
    ]
    for key, value in rows:
        val_str = str(value) if value is not None else "N/A"
        # Wrap long values across lines
        while len(val_str) > 38:
            lines.append("  " + _ROW_FORMAT.format(key, val_str[:38]))
            val_str = val_str[38:]
            key = ""
        lines.append("  " + _ROW_FORMAT.format(key, val_str))
    lines.append("  " + _ROW_SEPARATOR)
    lines.append("")
    return lines


def _render_list_table(title: str, headers: List[str], rows: List[List[str]]) -> List[str]:
    """Render a multi-column table with headers."""
    col_count = len(headers)
    if col_count == 2:
        fmt = "| {:<35s} | {:<38s} |"
        sep = _ROW_SEPARATOR
    elif col_count == 3:
        fmt = "| {:<22s} | {:<22s} | {:<26s} |"
        sep = "+" + "-" * 24 + "+" + "-" * 24 + "+" + "-" * 28 + "+"
    elif col_count == 4:
        fmt = "| {:<16s} | {:<16s} | {:<16s} | {:<20s} |"
        sep = "+" + "-" * 18 + "+" + "-" * 18 + "+" + "-" * 18 + "+" + "-" * 22 + "+"
    else:
        # Fallback: equal-width columns
        w = max(10, 76 // col_count)
        fmt = "| " + " | ".join(["{:<" + str(w) + "s}"] * col_count) + " |"
        sep = "+" + (("-" * (w + 2) + "+") * col_count)

    lines = [
        f"  {title}",
        "  " + sep,
        "  " + fmt.format(*[h[:38] for h in headers]),
        "  " + sep,
    ]
    for row in rows:
        padded = [str(c)[:38] if c is not None else "N/A" for c in row]
        while len(padded) < col_count:
            padded.append("")
        lines.append("  " + fmt.format(*padded[:col_count]))
    lines.append("  " + sep)
    lines.append("")
    return lines


def render_text_report(module_name: str, target: str, results: Dict[str, Any]) -> str:
    """
    Convert scan results into a human-readable text report.

    Produces formatted tables appropriate to each module type
    instead of dumping raw JSON.

    Args:
        module_name: The scanner module that produced the results.
        target: The scanned target.
        results: The results dictionary from a module's ``run()`` function.

    Returns:
        A multi-line string ready to write to a ``.txt`` file.
    """
    lines = _render_header(module_name, target)

    if module_name == "PortScanner":
        ports = results.get("open_ports", [])
        if ports:
            rows = [[str(p["port"]), p["status"], p.get("service", "Unknown")] for p in ports]
            lines += _render_list_table("OPEN PORTS", ["Port", "Status", "Service"], rows)
        else:
            lines.append("  No open ports discovered in scanned range.")
            lines.append("")
        scan_time = results.get("scan_duration_seconds")
        if scan_time is not None:
            lines.append(f"  Scan completed in {scan_time:.2f} seconds.")
            lines.append(f"  Ports scanned: {results.get('ports_scanned', 'N/A')}")
            lines.append("")

    elif module_name == "DNSLookup":
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        rows = []
        for rtype in record_types:
            records = results.get(rtype, [])
            if isinstance(records, list):
                for rec in records:
                    if isinstance(rec, dict):
                        rows.append([rtype, rec.get("value", str(rec)), str(rec.get("ttl", ""))])
                    else:
                        rows.append([rtype, str(rec), ""])
            elif records:
                rows.append([rtype, str(records), ""])
        if rows:
            lines += _render_list_table("DNS RECORDS", ["Type", "Value", "TTL"], rows)
        else:
            lines.append("  No DNS records found.")
            lines.append("")

    elif module_name == "WHOISLookup":
        if results.get("error"):
            lines.append(f"  Error: {results['error']}")
        else:
            kv = [
                ("Registrar", results.get("registrar")),
                ("Organization", results.get("organization")),
                ("Country", results.get("country")),
                ("Creation Date", results.get("creation_date")),
                ("Updated Date", results.get("updated_date")),
                ("Expiration Date", results.get("expiration_date")),
                ("Status", ", ".join(results.get("status", [])) if isinstance(results.get("status"), list) else results.get("status")),
            ]
            ns_list = results.get("name_servers", [])
            if ns_list:
                kv.append(("Name Servers", ", ".join(ns_list) if isinstance(ns_list, list) else str(ns_list)))
            lines += _render_kv_table("WHOIS INFORMATION", kv)
        lines.append("")

    elif module_name == "HeaderChecker":
        if results.get("error"):
            lines.append(f"  Error: {results['error']}")
        else:
            rows = []
            for h in results.get("headers", []):
                status = "Present" if h.get("present") else "Missing"
                severity = h.get("severity", "")
                value = h.get("value", "") if h.get("present") else ""
                rows.append([h.get("header", ""), status, severity, value[:20] if value else "-"])
            if rows:
                lines += _render_list_table(
                    "SECURITY HEADERS ANALYSIS",
                    ["Header", "Status", "Severity", "Value"],
                    rows,
                )
        lines.append("")

    elif module_name == "SubdomainFinder":
        subs = results.get("subdomains", [])
        if subs:
            rows = []
            for s in subs:
                rows.append([
                    s.get("subdomain", ""),
                    s.get("ip", ""),
                    str(s.get("status_code", "")),
                    s.get("response_time", ""),
                ])
            lines += _render_list_table(
                "DISCOVERED SUBDOMAINS",
                ["Subdomain", "IP Address", "HTTP Status", "Response Time"],
                rows,
            )
        else:
            lines.append("  No subdomains discovered.")
        lines.append("")

    elif module_name == "SSLAnalyzer":
        if results.get("error"):
            lines.append(f"  Error: {results['error']}")
        else:
            cert = results.get("certificate", {})
            kv = [
                ("Subject", cert.get("subject")),
                ("Issuer", cert.get("issuer")),
                ("Valid From", cert.get("valid_from")),
                ("Valid Until", cert.get("valid_until")),
                ("Days Remaining", cert.get("days_remaining")),
                ("Serial Number", cert.get("serial_number")),
                ("Signature Algorithm", cert.get("signature_algorithm")),
                ("TLS Version", results.get("tls_version")),
                ("Grade", results.get("grade")),
            ]
            lines += _render_kv_table("SSL/TLS CERTIFICATE", kv)
            sans = cert.get("san", [])
            if sans:
                san_rows = [[s] for s in sans]
                lines += _render_list_table("SUBJECT ALTERNATIVE NAMES", ["SAN Entry"], [[s] for s in sans])
        lines.append("")

    elif module_name == "TechDetector":
        techs = results.get("technologies", [])
        if techs:
            rows = [[t.get("name", ""), t.get("category", ""), t.get("detail", "")] for t in techs]
            lines += _render_list_table("DETECTED TECHNOLOGIES", ["Technology", "Category", "Detail"], rows)
        else:
            lines.append("  No technologies detected.")
        server_info = results.get("server_info", {})
        if server_info:
            kv = [(k, v) for k, v in server_info.items()]
            lines += _render_kv_table("SERVER INFORMATION", kv)
        lines.append("")

    else:
        # Fallback: render any dict as key/value
        kv = [(str(k), str(v)) for k, v in results.items() if k not in ("target", "domain")]
        if kv:
            lines += _render_kv_table("RESULTS", kv)

    lines.append(_SEPARATOR)
    lines.append(f"  Report generated by CyberShield Toolkit v{__version__}")
    lines.append(_SEPARATOR)

    return "\n".join(lines)
