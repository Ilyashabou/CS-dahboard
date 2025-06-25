"""
Dark web exposure checker using LeakLooker API.
"""

import os
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.helpers import extract_domain, format_result

# Load environment variables
load_dotenv()


class DarkwebChecker:
    """
    Checks for domain exposure on the dark web using LeakLooker API.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the darkweb checker.

        Args:
            api_key: LeakLooker API key (default: from environment)
        """
        self.api_key = api_key or os.getenv('LEAKLOOKER_API_KEY')
        self.api_url = "https://leak-lookup.com/api/search"

    def _check_domain_leaks(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        """
        Check if a domain has been exposed in data breaches.

        Args:
            domain: Domain to check

        Returns:
            List of breach dictionaries or None if error
        """
        if not self.api_key:
            return None

        headers = {
            "User-Agent": "CybersecDashboard"
        }

        payload = {
            "key": self.api_key,
            "type": "domain",
            "query": domain
        }

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                # Check if the response indicates success
                if data.get("error") == "false" and data.get("success") == "true":
                    results = data.get("message", {})

                    # Format the results into a list of breaches
                    breaches = []
                    for source, count in results.items():
                        if count > 0:
                            breaches.append({
                                "source": source,
                                "count": count,
                                "domain": domain
                            })
                    return breaches
                else:
                    # No breaches found or API error
                    return []
            else:
                # API error
                return None
        except requests.RequestException:
            return None

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Scan a domain for dark web exposure.

        Args:
            url: URL to scan

        Returns:
            Formatted scan results
        """
        domain = extract_domain(url)

        # Check domain for leaks
        breaches = self._check_domain_leaks(domain)

        if breaches is None:
            return format_result(
                scanner_name="Dark Web Exposure Checker",
                status="error",
                details={
                    "message": "Failed to check dark web exposure. Check your LeakLooker API key.",
                    "breaches": []
                }
            )

        # Format breach information
        formatted_breaches = []
        for breach in breaches:
            formatted_breaches.append({
                "name": breach.get("source", "Unknown"),
                "domain": breach.get("domain", domain),
                "count": breach.get("count", 0)
            })

        # Determine status based on number of breaches
        if len(formatted_breaches) > 0:
            status = "warning"
        else:
            status = "success"

        # Calculate total exposed records
        total_exposed = sum(breach.get("count", 0) for breach in formatted_breaches)

        return format_result(
            scanner_name="Dark Web Exposure Checker",
            status=status,
            details={
                "domain_checked": domain,
                "breaches": formatted_breaches,
                "total_breaches": len(formatted_breaches),
                "exposed_records": total_exposed
            }
        )
