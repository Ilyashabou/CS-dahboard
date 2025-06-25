"""
Nmap port scanner module.
"""

import subprocess
import re
from typing import Dict, Any, List, Optional

import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.helpers import extract_domain, format_result


class NmapScanner:
    """
    Runs a fast Nmap port scan on a target domain.
    """

    def __init__(self, timeout: int = 60, top_ports: int = 100):
        """
        Initialize the Nmap scanner.

        Args:
            timeout: Timeout for the scan in seconds
            top_ports: Number of top ports to scan
        """
        self.timeout = timeout
        self.top_ports = top_ports

    def _run_nmap(self, domain: str) -> Optional[str]:
        """
        Run Nmap command and return output.

        Args:
            domain: Domain to scan

        Returns:
            Nmap output as string or None if error
        """
        try:
            # Run a fast scan of top ports
            cmd = [
                "nmap",
                "-F",                      # Fast scan
                "--top-ports", str(self.top_ports),
                "-T4",                     # Aggressive timing
                "--open",                  # Only show open ports
                domain
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )

            if process.returncode != 0:
                return None

            return process.stdout
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Nmap output to extract port information.

        Args:
            output: Nmap command output

        Returns:
            List of dictionaries with port information
        """
        if not output:
            return []

        # Regular expression to match port lines
        port_pattern = r"(\d+)\/(\w+)\s+(\w+)\s+(.+)"

        ports = []
        for line in output.splitlines():
            match = re.search(port_pattern, line)
            if match:
                port_num, protocol, state, service = match.groups()
                ports.append({
                    "port": int(port_num),
                    "protocol": protocol,
                    "state": state,
                    "service": service.strip()
                })

        return ports

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL using Nmap.

        Args:
            url: URL to scan

        Returns:
            Formatted scan results
        """
        domain = extract_domain(url)
        output = self._run_nmap(domain)

        if output is None:
            return format_result(
                scanner_name="Nmap Port Scanner",
                status="error",
                details={
                    "message": f"Failed to run Nmap scan on {domain}",
                    "open_ports": []
                }
            )

        ports = self._parse_nmap_output(output)

        # Determine status based on potentially risky open ports
        risky_ports = {21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432}
        has_risky_ports = any(port["port"] in risky_ports for port in ports)

        status = "warning" if has_risky_ports else "success"

        return format_result(
            scanner_name="Nmap Port Scanner",
            status=status,
            details={
                "open_ports": ports,
                "total_open_ports": len(ports),
                "has_risky_ports": has_risky_ports
            }
        )
