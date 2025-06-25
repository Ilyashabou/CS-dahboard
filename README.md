# Cybersecurity Dashboard

A comprehensive web-based dashboard for monitoring and managing cybersecurity scans across multiple domains. This tool integrates various security scanning technologies and provides a unified interface for viewing results, scheduling automated scans, and receiving notifications.

## Features

### Security Scanners

- **SSL/TLS Certificate Checker**: Verifies certificate validity, expiration dates, and configuration
- **Port Scanner**: Uses Nmap to identify open ports and potentially risky services
- **Dark Web Exposure**: Checks if domain information has been leaked in data breaches
- **OWASP ZAP Integration**: Performs deep web application security scans

### Dashboard Functionality

- **Real-time Progress**: Live updates during scan execution
- **Detailed Reports**: Comprehensive HTML reports for all scan types
- **Scheduled Scans**: Automated scanning on daily, weekly, or monthly schedules
- **Manual Scan History**: Track and review previous scan results
- **AI-Powered Summaries**: Uses Google's Gemini API to create concise, actionable summaries
- **Telegram Notifications**: Sends scan results and CVE updates via Telegram
- **CVE News Updates**: Configurable schedule for receiving the latest CVE vulnerability information

### Core Components

- **Web Interface**: Flask-based dashboard with SocketIO for real-time updates
- **Report Generator**: Creates detailed HTML reports
- **AI Summarizer**: Uses Gemini API to create concise, actionable summaries
- **Telegram Integration**: Sends notifications with scan results

## Directory Structure

```
├── app.py                  # Main Flask application
├── main.py                 # CLI interface for running scans
├── schedule_runner.py      # Background scheduler for automated scans
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables and API keys
├── scanners/               # Security scanning modules
│   ├── ssl_checker.py      # SSL/TLS certificate verification
│   ├── nmap_scanner.py     # Port scanning with Nmap
│   ├── darkweb_checker.py  # Dark web exposure checks
│   └── zap_scanner.py      # OWASP ZAP integration
├── utils/                  # Utility functions
│   ├── helpers.py          # Common helper functions
│   ├── report_summarizer.py # AI-powered report summarization
│   ├── cve_news_service.py # CVE news fetching and processing
│   └── cve_scheduler.py    # Scheduler for CVE updates
├── templates/              # HTML templates
│   ├── index.html          # Main dashboard interface
│   ├── scan_report.html    # Report template
│   └── cve_news_component.html # CVE news display component
├── results/                # Scan results storage
│   ├── manual/             # Manual scan reports
│   └── scheduled/          # Scheduled scan reports
└── ZAP_2.16.1/             # OWASP ZAP installation
```

## Prerequisites

- Python 3.6+
- Nmap (for port scanning)
- OWASP ZAP 2.16.1 (for web application security scanning)
- WSL with Ubuntu (for ZAP scanning)
- API Keys:
  - LeakLooker API key (for dark web exposure checks)
  - Google Gemini API key (for AI-powered summaries)
  - Telegram Bot Token and Chat ID (for notifications)
  - NVD API key (for CVE news updates)

## Installation

1. Clone the repository
2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure API keys in the `.env` file:
   ```
   LEAKLOOKER_API_KEY=your_leaklooker_api_key
   GEMINI_API_KEY=your_gemini_api_key
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   TELEGRAM_CHAT_ID=your_telegram_chat_id
   NVD_API_KEY=your_nvd_api_key
   ```
4. Ensure OWASP ZAP is installed in the `ZAP_2.16.1` directory

## Usage

### Web Dashboard

Start the web dashboard:

```
python app.py
```

Access the dashboard at http://localhost:5000

### Command Line Interface

The project also includes a CLI for running scans directly:

```
python main.py [command] [url]
```

Available commands:
- `ssl`: Check SSL/TLS certificate
- `ports`: Scan open ports
- `darkweb`: Check dark web exposure
- `zapscan`: Run a ZAP security scan
- `fullscan`: Run all scans

Example:
```
python main.py fullscan https://example.com --output results.json
```

### Scheduled Scans

Scheduled scans are managed through the web interface. You can configure:

- Daily scans at a specific time
- Weekly scans on selected days of the week
- Monthly scans on selected days of the month
- One-time scans at a specific date and time

The scheduler runs in the background and automatically executes scans when they are due.

### CVE News Updates

The system can be configured to fetch and process the latest CVE (Common Vulnerabilities and Exposures) information on a schedule. Updates are summarized using the Gemini API and sent to Telegram.

## Technical Details

### Scanner Modules

#### SSL Checker
The `SSLChecker` class in `ssl_checker.py` verifies SSL/TLS certificates, checking validity, expiration dates, and other certificate details.

#### Nmap Scanner
The `NmapScanner` class in `nmap_scanner.py` performs port scans using the Nmap tool, identifying open ports, services, and potentially risky configurations.

#### Dark Web Checker
The `DarkwebChecker` class in `darkweb_checker.py` uses the LeakLooker API to check if a domain has been exposed in data breaches.

#### ZAP Scanner
The `ZAPScanner` class in `zap_scanner.py` integrates with OWASP ZAP to perform deep web application security scans. It runs ZAP through WSL Ubuntu for compatibility.

### Report Summarization

The `report_summarizer.py` module uses Google's Gemini API to create concise, actionable summaries of security scan reports. It extracts key information from HTML reports, sends it to the Gemini API for summarization, and formats the results for Telegram delivery.

### Scheduling System

The scheduling system in `schedule_runner.py` and `cve_scheduler.py` manages automated scans and CVE updates. It supports various schedule types (daily, weekly, monthly, custom) and ensures scans are executed at the appropriate times.

## AI Integration

This dashboard integrates with Google's Gemini AI to provide intelligent summarization of security scan reports. The AI analyzes the detailed technical findings and generates concise, actionable summaries highlighting:

- Critical security vulnerabilities
- Recommended remediation steps
- Prioritized action items
- Overall security posture assessment

These summaries are delivered via Telegram for quick review and action.

## Customization

### Adding New Scanners

The system is designed to be modular. To add a new scanner:

1. Create a new scanner module in the `scanners/` directory
2. Implement a `scan()` method that returns results in the standard format
3. Add the scanner to the scan sequence in `app.py`

### Modifying the Report Format

Edit the `templates/scan_report.html` file to customize the appearance and content of scan reports.

### Configuring the AI Summarizer

Adjust the prompt and parameters in `utils/report_summarizer.py` to customize the AI-generated summaries.

## Troubleshooting

- **API Key Issues**: Ensure all API keys are correctly set in the `.env` file
- **ZAP Scanner Errors**: Verify that the ZAP executable is correctly located in the ZAP_2.16.1 directory
- **Scheduler Problems**: Check the logs for any errors in the scheduler thread
- **Gemini API Errors**: The system will fall back to basic summaries if the AI API fails

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP ZAP for web application security scanning
- Google's Gemini AI for report summarization
- Telegram for notification delivery
