"""
SSL/TLS certificate checker module.
"""

import ssl
import socket
import datetime
from typing import Dict, Any, Tuple, Optional

import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.helpers import normalize_url, extract_domain, format_result


class SSLChecker:
    """
    Checks SSL/TLS certificate information for a given domain.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize the SSL checker.

        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout

    def get_certificate_info(self, domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Get SSL certificate information for a domain.

        Args:
            domain: Domain to check
            port: Port to connect to (default: 443)

        Returns:
            Dictionary with certificate information or None if error
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
            return None

    def check_expiry(self, cert: Dict[str, Any]) -> Tuple[bool, int]:
        """
        Check if a certificate is expired or about to expire.

        Args:
            cert: Certificate dictionary from get_certificate_info

        Returns:
            Tuple of (is_valid, days_remaining)
        """
        if not cert:
            return False, 0

        # Get expiry date
        expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        current_date = datetime.datetime.utcnow()

        # Calculate days remaining
        days_remaining = (expiry_date - current_date).days

        return days_remaining > 0, days_remaining

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL for SSL/TLS certificate information.

        Args:
            url: URL to scan

        Returns:
            Formatted scan results
        """
        domain = extract_domain(url)
        cert = self.get_certificate_info(domain)

        if not cert:
            return format_result(
                scanner_name="SSL/TLS Checker",
                status="error",
                details={
                    "message": f"Could not retrieve SSL certificate for {domain}",
                    "valid": False
                }
            )

        is_valid, days_remaining = self.check_expiry(cert)

        # Extract certificate details
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        status = "success" if is_valid and days_remaining > 30 else "warning"

        return format_result(
            scanner_name="SSL/TLS Checker",
            status=status,
            details={
                "valid": is_valid,
                "days_remaining": days_remaining,
                "issuer": issuer.get('organizationName', 'Unknown'),
                "subject": subject.get('commonName', 'Unknown'),
                "valid_from": cert.get('notBefore', 'Unknown'),
                "valid_until": cert.get('notAfter', 'Unknown'),
                "version": cert.get('version', 'Unknown')
            }
        )
