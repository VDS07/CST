from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def print_banner():
    """Prints the application banner."""
    banner = """[bold cyan]
========================================
         CyberShield Toolkit
========================================
[/bold cyan]"""
    console.print(banner)

def print_success(message: str):
    console.print(f"[bold green][+][/bold green] {message}")

def print_error(message: str):
    console.print(f"[bold red][-][/bold red] {message}")

def print_info(message: str):
    console.print(f"[bold blue][*][/bold blue] {message}")

def create_table(title: str, columns: list[str]) -> Table:
    """Creates a basic rich Table."""
    table = Table(title=title, show_header=True, header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    return table
