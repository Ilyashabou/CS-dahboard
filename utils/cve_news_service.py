"""CVE News Service - Fetches CVE data from NVD API, summarizes with Gemini, and sends to Telegram."""
import os
import json
import time
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cve_news.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cve_news_service")

# Load environment variables
load_dotenv()

# Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY", "bf61d2f7-cd6b-42ee-9732-7d75012faff3")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# File paths
NEWS_CACHE_FILE = "news_log.json"

# API settings
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_API_RETRIES = 3
MAX_CVES_TO_FETCH = 20  # Limit the number of CVEs to fetch

def load_news_cache():
    """Load the news cache from file."""
    try:
        if os.path.exists(NEWS_CACHE_FILE):
            with open(NEWS_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading news cache: {str(e)}")
        return []

def save_news_cache(news_items):
    """Save the news cache to file."""
    try:
        with open(NEWS_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(news_items, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving news cache: {str(e)}")
        return False

def fetch_cves(days_back=1):
    """Fetch CVEs from NVD API."""
    # Calculate the date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days_back)
    
    # Format dates for the API
    pub_start_date = start_date.strftime("%Y-%m-%dT00:00:00.000")
    pub_end_date = end_date.strftime("%Y-%m-%dT23:59:59.999")
    
    # Prepare request parameters
    params = {
        "pubStartDate": pub_start_date,
        "pubEndDate": pub_end_date,
        "resultsPerPage": MAX_CVES_TO_FETCH
        # Removed both sortBy and sortOrder parameters as they cause 404 errors
    }
    
    headers = {
        "apiKey": NVD_API_KEY
    }
    
    # Make the request with retries
    for attempt in range(MAX_API_RETRIES):
        try:
            logger.info(f"Fetching CVEs from {pub_start_date} to {pub_end_date}")
            logger.info(f"Request URL: {NVD_API_URL}")
            logger.info(f"Request params: {params}")
            logger.info(f"Request headers: {headers}")
            response = requests.get(NVD_API_URL, params=params, headers=headers)
            
            logger.info(f"Response status code: {response.status_code}")
            logger.info(f"Response URL: {response.url}")
            
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            elif response.status_code == 429:  # Rate limit
                wait_time = 10 * (attempt + 1)  # Exponential backoff
                logger.warning(f"Rate limit hit, waiting {wait_time} seconds")
                time.sleep(wait_time)
            else:
                logger.error(f"API error: {response.status_code} - {response.text}")
                break
        except Exception as e:
            logger.error(f"Error fetching CVEs: {str(e)}")
            time.sleep(5)
    
    return []

def process_cve_data(vulnerabilities):
    """Process and format CVE data."""
    cve_items = []
    
    for vuln in vulnerabilities:
        try:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            
            # Get metrics
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else \
                      metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else {}
            
            cvss_data = cvss_v3.get("cvssData", {}) if cvss_v3 else {}
            base_score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", "N/A")
            
            # Get descriptions
            descriptions = cve.get("descriptions", [])
            description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "No description available")
            
            # Get references
            references = []
            for ref in cve.get("references", [])[:3]:  # Limit to first 3 references
                references.append(ref.get("url", ""))
            
            # Create CVE item
            cve_item = {
                "id": cve_id,
                "published": cve.get("published", ""),
                "description": description,
                "cvss_score": base_score,
                "severity": severity,
                "references": references
            }
            
            cve_items.append(cve_item)
        except Exception as e:
            logger.error(f"Error processing CVE: {str(e)}")
    
    # Sort by severity and score
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}
    cve_items.sort(key=lambda x: (severity_order.get(x["severity"], 999), -float(x["cvss_score"]) if isinstance(x["cvss_score"], (int, float)) else 0))
    
    return cve_items

def summarize_with_gemini(cve_items, max_tokens=1000):
    """Use Gemini API to summarize CVE data."""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "":
        logger.warning("Gemini API key not configured")
        return create_fallback_summary(cve_items)
    
    # Prepare the CVE data for the prompt
    cve_text = ""
    for cve in cve_items:  # Include all CVEs, not just top 10
        cve_text += f"ID: {cve['id']}\n"
        cve_text += f"Severity: {cve['severity']}\n"
        cve_text += f"CVSS Score: {cve['cvss_score']}\n"
        cve_text += f"Description: {cve['description']}\n"
        cve_text += f"References: {', '.join(cve['references'])}\n\n"
    
    # API endpoints to try
    endpoints = [
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1/models/gemini-1.0-pro:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    ]
    
    prompt = f"""
    Create a comprehensive security alert for the following CVE (Common Vulnerabilities and Exposures) data.
    
    Format requirements:
    1. Use clear section headers with emoji indicators (🔴 for CRITICAL, 🟠 for HIGH, 🟡 for MEDIUM, 🟢 for LOW)
    2. Group vulnerabilities by severity (CRITICAL, HIGH, MEDIUM, LOW)
    3. For each CVE, include:
       - Bold CVE ID and CVSS score
       - Concise description in plain language (max 150 characters)
       - Direct link to NVD page using format: 🔗 [View Details](https://nvd.nist.gov/vuln/detail/CVE-ID)
    4. Use markdown formatting (bold with * for emphasis)
    5. Keep sentences short and avoid technical jargon
    6. Include ALL CVEs provided, not just a subset
    7. Format as a Telegram message with proper markdown
    
    CVE DATA:
    {cve_text}
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
                logger.info(f"Attempt {attempt+1}/{MAX_API_RETRIES} - Sending request to: {endpoint}")
                
                response = requests.post(url, json=payload, headers=headers)
                logger.info(f"Response status: {response.status_code}")
                
                # Handle specific error codes
                if response.status_code == 429:
                    logger.warning("Rate limit exceeded, waiting before retry...")
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue
                elif response.status_code == 404:
                    logger.warning("API endpoint not found, trying next endpoint")
                    break  # Try next endpoint
                
                # If successful, process the response
                if response.status_code == 200:
                    result = response.json()
                    if "candidates" in result and len(result["candidates"]) > 0:
                        if "content" in result["candidates"][0] and "parts" in result["candidates"][0]["content"]:
                            return result["candidates"][0]["content"]["parts"][0]["text"]
                    
                    logger.warning(f"Unexpected response format: {result}")
                    break  # Try next endpoint
            
            except Exception as e:
                logger.error(f"Error with endpoint {endpoint}: {str(e)}")
                time.sleep(1)  # Wait before retry
    
    # If all API attempts failed, use fallback summary
    logger.warning("All Gemini API attempts failed, using fallback summary")
    return create_fallback_summary(cve_items)

def create_fallback_summary(cve_items):
    """Create a formatted summary without using the Gemini API"""
    try:
        summary = "*Daily CVE Security Update*\n\n"
        
        if not cve_items:
            return summary + "No new CVEs found in the specified time period."
        
        # Group by severity
        by_severity = {}
        for cve in cve_items:
            severity = cve.get("severity", "N/A")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(cve)
        
        # Add summary by severity with clear sections and emojis
        severity_emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "N/A": "⚪"
        }
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A"]:
            if severity in by_severity:
                items = by_severity[severity]
                emoji = severity_emojis.get(severity, "")
                summary += f"\n{emoji} *{severity} SEVERITY* ({len(items)} found)\n" + "-"*30 + "\n"
                
                # Include all CVEs in each severity category
                for i, cve in enumerate(items):
                    # Format with bold for CVE ID and severity
                    summary += f"*{i+1}. {cve['id']}* - CVSS: *{cve['cvss_score']}*\n"
                    
                    # Add description with simplified text
                    desc = cve['description']
                    if len(desc) > 150:
                        desc = desc[:147] + "..."
                    summary += f"{desc}\n"
                    
                    # Add direct NVD link
                    summary += f"🔗 [View Details](https://nvd.nist.gov/vuln/detail/{cve['id']})\n\n"
                
        return summary
    except Exception as e:
        logger.error(f"Error creating fallback summary: {str(e)}")
        return "*Daily CVE Security Update*\n\nError generating summary. Please check the logs."

def send_to_telegram(message):
    """Send a message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "" or \
       not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "":
        logger.warning("Telegram API not configured")
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
        logger.info("Message sent to Telegram successfully")
        return True
    except Exception as e:
        logger.error(f"Error sending to Telegram: {str(e)}")
        return False

def process_daily_cves(days_back=1):
    """Process daily CVEs, summarize them, and send to Telegram."""
    logger.info("Starting daily CVE processing")
    
    # Fetch CVEs
    vulnerabilities = fetch_cves(days_back)
    
    if not vulnerabilities:
        logger.warning("No vulnerabilities found")
        message = "*Daily CVE Security Update*\n\nNo new CVEs found in the specified time period."
        send_to_telegram(message)
        return {
            "success": False,
            "message": "No vulnerabilities found"
        }
    
    # Process CVE data
    cve_items = process_cve_data(vulnerabilities)
    
    # Summarize with Gemini
    summary = summarize_with_gemini(cve_items)
    
    # Send to Telegram
    success = send_to_telegram(summary)
    
    # Save to cache but don't display in UI
    timestamp = int(datetime.now().timestamp())
    cache_entry = {
        "timestamp": timestamp,
        "summary": "CVE updates are now sent directly to Telegram. Check your Telegram for the latest security alerts.",
        "cve_count": len(cve_items),
        "sent_to_telegram": success,
        "days_back": days_back
    }
    
    news_cache = load_news_cache()
    news_cache.append(cache_entry)
    save_news_cache(news_cache)
    
    logger.info(f"Processed {len(cve_items)} CVEs and sent to Telegram")
    
    return {
        "success": True,
        "cve_count": len(cve_items),
        "days_back": days_back,
        "message": "CVE updates sent to Telegram"
    }

# For testing
if __name__ == "__main__":
    result = process_daily_cves()
    print(json.dumps(result, indent=2))