#!/usr/bin/env python3
"""
Cybersecurity Dashboard CLI - A tool for scanning domains for security issues.
"""

import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from typing import Dict, Any, List, Optional
import json
from dotenv import load_dotenv

from scanners.ssl_checker import SSLChecker
from scanners.nmap_scanner import NmapScanner
from scanners.darkweb_checker import DarkwebChecker
from scanners.zap_scanner import ZAPScanner
from utils.helpers import normalize_url

# Load environment variables
load_dotenv()

# Initialize console
console = Console()


def print_ssl_results(results: Dict[str, Any]):
    """Print SSL scan results in a formatted way."""
    details = results["details"]

    if results["status"] == "error":
        console.print(f"[bold red]❌ {details['message']}[/]")
        return

    # Create a table for SSL results
    table = Table(title="SSL/TLS Certificate Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Valid", "✅ Yes" if details["valid"] else "❌ No")
    table.add_row("Days Remaining", f"{details['days_remaining']} days")
    table.add_row("Issuer", details["issuer"])
    table.add_row("Subject", details["subject"])
    table.add_row("Valid From", details["valid_from"])
    table.add_row("Valid Until", details["valid_until"])

    # Add emoji based on status
    emoji = "✅" if results["status"] == "success" else "⚠️"

    console.print(Panel(table, title=f"{emoji} SSL/TLS Certificate Check"))


def print_nmap_results(results: Dict[str, Any]):
    """Print Nmap scan results in a formatted way."""
    details = results["details"]

    if results["status"] == "error":
        console.print(f"[bold red]❌ {details['message']}[/]")
        return

    # Create a table for open ports
    table = Table(title=f"Open Ports ({details['total_open_ports']} found)")
    table.add_column("Port", style="cyan")
    table.add_column("Protocol", style="green")
    table.add_column("State", style="green")
    table.add_column("Service", style="green")

    for port in details["open_ports"]:
        table.add_row(
            str(port["port"]),
            port["protocol"],
            port["state"],
            port["service"]
        )

    # Add emoji based on status
    emoji = "✅" if results["status"] == "success" else "⚠️"
    title = f"{emoji} Port Scan"
    if details["has_risky_ports"]:
        title += " (Potentially risky ports found)"

    console.print(Panel(table, title=title))


def print_vulnerability_results(results: Dict[str, Any]):
    """Print vulnerability scan results in a formatted way."""
    details = results["details"]

    if results["status"] == "error":
        if "message" in details:
            console.print(f"[bold red]❌ {details['message']}[/]")
        else:
            console.print("[bold red]❌ Vulnerability scan failed[/]")
        return

    # Check if running in fallback mode
    fallback_mode = details.get("fallback_mode", False)
    if fallback_mode and "message" in details:
        console.print(f"[bold yellow]⚠️ {details['message']}[/]")

    # Create a table for vulnerabilities
    table = Table(title=f"Vulnerabilities ({details['total_vulnerabilities']} found)")
    table.add_column("Severity", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Description", style="green")

    for vuln in details["vulnerabilities"]:
        # Map severity level (3=High, 2=Medium, 1=Low, 0=Info)
        severity_text = "High" if vuln["severity"] == 3 else "Medium" if vuln["severity"] == 2 else "Low" if vuln["severity"] == 1 else "Info"
        severity_color = "red" if vuln["severity"] == 3 else "yellow" if vuln["severity"] == 2 else "green"

        table.add_row(
            f"[{severity_color}]{severity_text}[/]",
            vuln["name"],
            vuln["description"][:50] + "..." if len(vuln["description"]) > 50 else vuln["description"]
        )

    # Add emoji based on status
    emoji = "✅" if results["status"] == "success" else "⚠️" if results["status"] == "warning" else "❌"

    # Create title with mode indicator
    summary = f"High: {details['high_risk_vulnerabilities']} | Medium: {details['medium_risk_vulnerabilities']} | Low: {details['low_risk_vulnerabilities']}"
    title = f"{emoji} Vulnerability Scan ({summary})"
    if fallback_mode:
        title += " [Basic Mode]"

    console.print(Panel(table, title=title))


def print_darkweb_results(results: Dict[str, Any]):
    """Print dark web exposure results in a formatted way."""
    details = results["details"]

    if results["status"] == "error":
        console.print(f"[bold red]❌ {details['message']}[/]")
        return

    # Create a table for breaches
    table = Table(title=f"Data Breaches ({details['total_breaches']} found)")
    table.add_column("Source", style="cyan")
    table.add_column("Domain", style="green")
    table.add_column("Records", style="green")

    for breach in details["breaches"]:
        table.add_row(
            breach["name"],
            breach["domain"],
            f"{breach['count']:,}"
        )

    # Add emoji based on status
    emoji = "✅" if results["status"] == "success" else "⚠️"

    console.print(Panel(
        table,
        title=f"{emoji} Dark Web Exposure Check (Domain: {details['domain_checked']})"
    ))


@click.group()
def cli():
    """Cybersecurity Dashboard CLI - Scan domains for security issues."""
    pass


@cli.command()
@click.argument("url")
@click.option("--output", "-o", help="Save results to JSON file")
def ssl(url, output):
    """Check SSL/TLS certificate for a domain."""
    url = normalize_url(url)
    console.print(f"[bold]Checking SSL/TLS certificate for {url}...[/]")

    scanner = SSLChecker()
    results = scanner.scan(url)

    print_ssl_results(results)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")


@cli.command()
@click.argument("url")
@click.option("--output", "-o", help="Save results to JSON file")
def ports(url, output):
    """Scan open ports on a domain."""
    url = normalize_url(url)
    console.print(f"[bold]Scanning ports on {url}...[/]")

    scanner = NmapScanner()
    results = scanner.scan(url)

    print_nmap_results(results)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")



@cli.command()
@click.argument("url")
@click.option("--output", "-o", help="Save results to JSON file")
def zapscan(url, output):
    """Run a deep scan with OWASP ZAP (via WSL Ubuntu).
    Saves an HTML report and prints status."""
    url = normalize_url(url)
    console.print(f"[bold]Running OWASP ZAP deep scan for {url}...[/]")

    scanner = ZAPScanner()
    # Output HTML path (relative to project root)
    output_html = "results/zap_report.html"
    results = scanner.scan(url, output_html)

    # Print summary
    if results["status"] == "success":
        console.print(f"[green]ZAP scan completed. Report: {output_html}[/]")
    else:
        console.print(f"[bold red]ZAP scan failed: {results['details'].get('message', 'Unknown error')}[/]")

    # Save results (including report path) to output JSON if requested
    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")

@cli.command()
@click.argument("url")
@click.option("--output", "-o", help="Save results to JSON file")
def darkweb(url, output):
    """Check for dark web exposure."""
    url = normalize_url(url)
    console.print(f"[bold]Checking dark web exposure for {url}...[/]")

    scanner = DarkwebChecker()
    results = scanner.scan(url)

    print_darkweb_results(results)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")


@cli.command()
@click.argument("url")
@click.option("--output", "-o", help="Save results to JSON file")
def fullscan(url, output):
    """Run all scans on a domain."""
    url = normalize_url(url)
    console.print(f"[bold]Running full security scan on {url}...[/]")

    all_results = {}

    with Progress() as progress:
        task = progress.add_task("[cyan]Running scans...", total=3)

        # SSL scan
        console.print("\n[bold cyan]SSL/TLS Certificate Check[/]")
        scanner = SSLChecker()
        results = scanner.scan(url)
        print_ssl_results(results)
        all_results["ssl"] = results
        progress.update(task, advance=1)

        # Port scan
        console.print("\n[bold cyan]Port Scan[/]")
        scanner = NmapScanner()
        results = scanner.scan(url)
        print_nmap_results(results)
        all_results["ports"] = results
        progress.update(task, advance=1)

        # Dark web scan
        console.print("\n[bold cyan]Dark Web Exposure Check[/]")
        scanner = DarkwebChecker()
        results = scanner.scan(url)
        print_darkweb_results(results)
        all_results["darkweb"] = results
        progress.update(task, advance=1)

    if output:
        with open(output, "w") as f:
            json.dump(all_results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")


if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/]")
        sys.exit(1)
