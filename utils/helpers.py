"""
Helper functions for the cybersecurity dashboard.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Union


def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding http:// if no scheme is present.
    
    Args:
        url: The URL to normalize
        
    Returns:
        Normalized URL with scheme
    """
    if not url.startswith(('http://', 'https://')):
        return f'http://{url}'
    return url


def extract_domain(url: str) -> str:
    """
    Extract the domain from a URL.
    
    Args:
        url: The URL to extract domain from
        
    Returns:
        Domain name without scheme or path
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
        
    return domain


def format_result(scanner_name: str, status: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format scanner results in a consistent way.
    
    Args:
        scanner_name: Name of the scanner
        status: Status of the scan (success, warning, error)
        details: Detailed results from the scan
        
    Returns:
        Formatted result dictionary
    """
    return {
        'scanner': scanner_name,
        'status': status,
        'details': details,
        'timestamp': __import__('datetime').datetime.now().isoformat()
    }
