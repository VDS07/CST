import os
import datetime
import argparse
import json
from rich.prompt import Prompt
from utils.formatter import console, print_banner, print_success, print_error, print_info, create_table
from utils.logger import setup_logger
from modules import port_scanner, dns_lookup, whois_lookup, header_checker, subdomain_finder

logger = setup_logger("main")

def save_report(module_name: str, target: str, results: dict):
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace("://", "_").replace("/", "_")
    base_filename = f"reports/{module_name}_{sanitized_target}_{timestamp}"
    
    # Save JSON report
    json_filename = f"{base_filename}.json"
    try:
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        logger.debug(f"JSON report saved to {json_filename}")
    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")
        
    # Save Text report
    txt_filename = f"{base_filename}.txt"
    try:
        with open(txt_filename, "w", encoding="utf-8") as f:
            f.write(f"--- CyberShield Toolkit Report ---\n")
            f.write(f"Module: {module_name}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'-'*35}\n\n")
            f.write(json.dumps(results, indent=4))
        logger.debug(f"TXT report saved to {txt_filename}")
        print_success(f"Report saved to [bold cyan]{json_filename}[/bold cyan] and [bold cyan]{txt_filename}[/bold cyan]")
    except Exception as e:
        logger.error(f"Error saving TXT report: {e}")
        print_error(f"Error saving report: {e}")

def run_port_scanner(target: str):
    with console.status(f"[bold green]Scanning ports on {target}...", spinner="dots"):
        results = port_scanner.run(target)
    
    if results.get("open_ports"):
        table = create_table("Open Ports", ["Port", "Status", "Service"])
        for p in results["open_ports"]:
            table.add_row(str(p["port"]), f"[green]{p['status']}[/green]", p["service"])
        console.print(table)
    else:
        print_info("No open ports found in range 1-1024.")
        
    save_report("PortScanner", target, results)

def run_dns_lookup(domain: str):
    with console.status(f"[bold green]Looking up DNS records for {domain}...", spinner="dots"):
        results = dns_lookup.run(domain)
        
    table = create_table("DNS Records", ["Type", "Value"])
    for a in results.get("A", []):
        table.add_row("A", a)
    for mx in results.get("MX", []):
        table.add_row("MX", mx)
    for ns in results.get("NS", []):
        table.add_row("NS", ns)
        
    if table.row_count > 0:
        console.print(table)
    else:
        print_info("No common DNS records found.")
        
    save_report("DNSLookup", domain, results)

def run_whois_lookup(domain: str):
    with console.status(f"[bold green]Performing WHOIS lookup for {domain}...", spinner="dots"):
        results = whois_lookup.run(domain)
        
    if results.get("error"):
        print_error(results["error"])
    else:
        table = create_table("WHOIS Information", ["Property", "Value"])
        table.add_row("Registrar", str(results.get("registrar")))
        table.add_row("Creation Date", str(results.get("creation_date")))
        table.add_row("Expiration Date", str(results.get("expiration_date")))
        console.print(table)
        
    save_report("WHOISLookup", domain, results)

def run_header_checker(target: str):
    with console.status(f"[bold green]Checking security headers for {target}...", spinner="dots"):
        results = header_checker.run(target)
        
    if results.get("error"):
        print_error(results["error"])
    else:
        table = create_table("Security Headers", ["Header", "Status"])
        for h in results.get("found", []):
            table.add_row(h, "[bold green]Found[/bold green]")
        for h in results.get("missing", []):
            table.add_row(h, "[bold red]Missing[/bold red]")
        console.print(table)
        
    save_report("HeaderChecker", target, results)

def run_subdomain_finder(domain: str):
    with console.status(f"[bold green]Finding subdomains for {domain}...", spinner="dots"):
        results = subdomain_finder.run(domain)
        
    if results.get("subdomains"):
        table = create_table("Discovered Subdomains", ["Subdomain", "IP Address"])
        for s in results["subdomains"]:
            table.add_row(s["subdomain"], s["ip"])
        console.print(table)
    else:
        print_info("No common subdomains found.")
        
    save_report("SubdomainFinder", domain, results)

def interactive_menu():
    while True:
        print_banner()
        console.print("[1] Port Scanner", style="bold yellow")
        console.print("[2] DNS Lookup", style="bold yellow")
        console.print("[3] WHOIS Lookup", style="bold yellow")
        console.print("[4] Security Headers Checker", style="bold yellow")
        console.print("[5] Subdomain Finder", style="bold yellow")
        console.print("[6] Exit", style="bold yellow")
        console.print("="*40, style="bold cyan")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == '1':
            target = Prompt.ask("Enter target IP or Domain")
            if target: run_port_scanner(target)
        elif choice == '2':
            domain = Prompt.ask("Enter Domain (e.g., google.com)")
            if domain: run_dns_lookup(domain)
        elif choice == '3':
            domain = Prompt.ask("Enter Domain (e.g., google.com)")
            if domain: run_whois_lookup(domain)
        elif choice == '4':
            target = Prompt.ask("Enter Target Domain or URL (e.g., google.com)")
            if target: run_header_checker(target)
        elif choice == '5':
            domain = Prompt.ask("Enter Domain (e.g., example.com)")
            if domain: run_subdomain_finder(domain)
        elif choice == '6':
            print_info("Exiting CyberShield Toolkit. Stay safe!")
            break
            
        console.print("\n")

def parse_args():
    parser = argparse.ArgumentParser(description="CyberShield Toolkit CLI")
    parser.add_argument("--module", choices=["port_scanner", "dns_lookup", "whois_lookup", "header_checker", "subdomain_finder"],
                        help="The module to run.")
    parser.add_argument("--target", help="The target domain or IP address.")
    return parser.parse_args()

def main():
    args = parse_args()
    
    if args.module and args.target:
        logger.info(f"Running via CLI: module={args.module}, target={args.target}")
        print_banner()
        if args.module == "port_scanner":
            run_port_scanner(args.target)
        elif args.module == "dns_lookup":
            run_dns_lookup(args.target)
        elif args.module == "whois_lookup":
            run_whois_lookup(args.target)
        elif args.module == "header_checker":
            run_header_checker(args.target)
        elif args.module == "subdomain_finder":
            run_subdomain_finder(args.target)
    elif args.module or args.target:
        print_error("Both --module and --target must be provided for CLI execution.")
    else:
        logger.info("Starting interactive menu.")
        interactive_menu()

if __name__ == "__main__":
    main()
