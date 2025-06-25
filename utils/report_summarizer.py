"""
Report summarizer module that uses Gemini AI to summarize scan reports and sends them to Telegram.
"""
import re
import json
import requests
import time
import os
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration - load from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")  # Load from environment variable
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")  # Load from environment variable
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")  # Load from environment variable

# API settings
USE_GEMINI_API = True  # Set to False to skip Gemini API and use only the fallback summary
MAX_API_RETRIES = 2    # Number of retries for API calls

def extract_report_content(html_path):
    """Extract key information from an HTML report file."""
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract title
        title = soup.title.string if soup.title else "Cybersecurity Scan Report"
        
        # Extract main content (simplify HTML to text)
        content = []
        for section in soup.select('.scan-section'):
            section_title = section.select_one('.subtitle')
            section_title_text = section_title.get_text(strip=True) if section_title else "Unknown Section"
            
            # Extract status badges
            status_badge = section.select_one('.status-badge')
            status = status_badge.get_text(strip=True) if status_badge else "Unknown"
            
            # Extract key information
            info_items = []
            for item in section.select('.info-list li'):
                info_items.append(item.get_text(strip=True))
            
            # Add to content
            content.append(f"## {section_title_text} - {status}")
            if info_items:
                content.append("\n".join(info_items))
        
        return {
            "title": title,
            "content": "\n\n".join(content),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {
            "title": "Error Extracting Report",
            "content": f"Failed to extract report content: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def extract_zap_report_content(html_path):
    """Extract key information from a ZAP HTML report file."""
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract alerts
        alerts = []
        alert_items = soup.select('.alert')
        
        if not alert_items:  # Try alternative selectors for ZAP reports
            alert_items = soup.select('tr.risk-high, tr.risk-medium, tr.risk-low')
        
        for alert in alert_items[:10]:  # Limit to top 10 alerts
            risk = alert.get('class', ['unknown'])[0].replace('risk-', '') if 'risk-' in str(alert.get('class', [])) else 'unknown'
            name = alert.select_one('td:first-child, .alertHeader')
            name_text = name.get_text(strip=True) if name else "Unknown Alert"
            alerts.append(f"- {risk.upper()}: {name_text}")
        
        # If no structured alerts found, extract summary text
        if not alerts:
            summary = soup.select_one('#summary, .summary')
            if summary:
                alerts = [summary.get_text(strip=True)]
            else:
                # Last resort: get text from the body
                body_text = soup.body.get_text(strip=True) if soup.body else "No content found"
                # Truncate to reasonable length
                alerts = [body_text[:500] + "..." if len(body_text) > 500 else body_text]
        
        return {
            "title": "ZAP Security Scan Results",
            "content": "## Top Security Alerts\n" + "\n".join(alerts),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {
            "title": "Error Extracting ZAP Report",
            "content": f"Failed to extract ZAP report content: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def create_fallback_summary(text):
    """Create a basic summary without using the Gemini API"""
    try:
        # Extract basic information from the text
        url_match = re.search(r'URL: ([^\n]+)', text) or re.search(r'for ([^\n]+)', text)
        url = url_match.group(1) if url_match else "Unknown URL"
        
        # Look for critical findings
        findings = []
        if 'SSL Scan' in text and 'success' in text:
            findings.append("✅ SSL configuration appears secure")
        elif 'SSL Scan' in text and 'error' in text:
            findings.append("⚠️ SSL configuration issues detected")
            
        if 'Port Scan' in text:
            port_match = re.search(r'Total Open Ports: (\d+)', text)
            if port_match:
                findings.append(f"🔍 Found {port_match.group(1)} open ports")
        
        if 'Dark Web Exposure' in text and 'No breaches found' in text:
            findings.append("✅ No dark web exposures found")
        elif 'Dark Web Exposure' in text and 'Breaches:' in text:
            findings.append("⚠️ Potential dark web exposures detected")
        
        if 'ZAP Security Scan' in text and 'RISK-HIGH' in text.upper():
            findings.append("🚨 High-risk vulnerabilities detected in ZAP scan")
        elif 'ZAP Security Scan' in text:
            findings.append("🔍 ZAP security scan completed")
        
        # Create a simple summary
        summary = f"Security scan summary for {url}\n\n"
        summary += "\n".join(findings) if findings else "Scan completed, but no specific findings could be extracted."
        
        return summary
    except Exception as e:
        return f"Error creating fallback summary: {str(e)}"

def summarize_with_gemini(text, max_tokens=500):
    """Use Gemini API to summarize text."""
    # If Gemini API is disabled, use fallback summary
    if not USE_GEMINI_API:
        print("Gemini API is disabled, using fallback summary")
        return create_fallback_summary(text)
    
    # Check API key
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return "⚠️ Gemini API key not configured. Please set your API key in report_summarizer.py."
    
    # API endpoints to try
    endpoints = [
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.0-pro:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    ]
    
    prompt = f"""
    Summarize the following cybersecurity scan report in a concise, actionable format.
    Focus on the most critical findings, vulnerabilities, and recommended actions.
    Format the summary with clear sections and bullet points.
    
    REPORT CONTENT:
    {text}
    """
    
    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": max_tokens,
            "topP": 0.8,
            "topK": 40
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    # Try each endpoint with retries
    for endpoint in endpoints:
        for attempt in range(MAX_API_RETRIES):
            try:
                url = f"{endpoint}?key={GEMINI_API_KEY}"
                print(f"Attempt {attempt+1}/{MAX_API_RETRIES} - Sending request to: {endpoint}")
                
                response = requests.post(url, json=payload, headers=headers)
                print(f"Response status: {response.status_code}")
                
                # Handle specific error codes
                if response.status_code == 429:
                    print("Rate limit exceeded, waiting before retry...")
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue
                elif response.status_code == 404:
                    print("API endpoint not found, trying next endpoint")
                    break  # Try next endpoint
                
                # If successful, process the response
                if response.status_code == 200:
                    result = response.json()
                    if "candidates" in result and len(result["candidates"]) > 0:
                        if "content" in result["candidates"][0] and "parts" in result["candidates"][0]["content"]:
                            return result["candidates"][0]["content"]["parts"][0]["text"]
                    
                    print(f"Unexpected response format: {result}")
                    break  # Try next endpoint
            
            except Exception as e:
                print(f"Error with endpoint {endpoint}: {str(e)}")
                time.sleep(1)  # Wait before retry
    
    # If all API attempts failed, use fallback summary
    print("All Gemini API attempts failed, using fallback summary")
    return create_fallback_summary(text)

def send_to_telegram(message):
    """Send a message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" or \
       not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "YOUR_TELEGRAM_CHAT_ID":
        print("⚠️ Telegram API not configured. Please set your bot token and chat ID in report_summarizer.py.")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error sending to Telegram: {str(e)}")
        return False

def process_scan_reports(scan_report_path, zap_report_path, url, scan_id):
    """Process both reports, summarize them with Gemini, and send to Telegram."""
    # Extract content from both reports
    scan_content = extract_report_content(scan_report_path)
    zap_content = extract_zap_report_content(zap_report_path)
    
    # Combine reports
    combined_text = f"""
    # Security Scan Summary for {url}
    Scan ID: {scan_id}
    Time: {scan_content['timestamp']}
    
    ## Main Scan Findings
    {scan_content['content']}
    
    ## ZAP Security Scan
    {zap_content['content']}
    """
    
    # Summarize with Gemini
    summary = summarize_with_gemini(combined_text)
    
    # Prepare message for Telegram
    message = f"""
*Security Scan Summary for {url}*
Scan ID: `{scan_id}`
Time: {scan_content['timestamp']}

{summary}
    """
    
    # Send to Telegram
    success = send_to_telegram(message)
    
    return {
        "success": success,
        "summary": summary
    }
