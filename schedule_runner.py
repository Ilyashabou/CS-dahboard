import os
import json
import time
import threading
from datetime import datetime, timedelta

# Flags for module availability - will be set in run_scheduled_scans
SUMMARIZER_AVAILABLE = False
CVE_SCHEDULER_AVAILABLE = False

SCHEDULED_SCANS_FILE = 'scheduled_scans.json'
SCAN_RESULTS_DIR = 'results'

# Helper to load and save scheduled scans
lock = threading.Lock()
def load_scheduled_scans():
    with lock:
        try:
            with open(SCHEDULED_SCANS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []

def save_scheduled_scans(scans):
    with lock:
        with open(SCHEDULED_SCANS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scans, f, indent=2)

def is_due(scan):
    now = datetime.now()
    last_run = scan.get('last_run')
    if last_run:
        last_run_dt = datetime.fromisoformat(last_run)
    else:
        last_run_dt = None
    scan_type = scan.get('type')
    if scan_type == 'daily':
        # Run once per day at scan['dailyTime']
        due_time = datetime.strptime(scan['dailyTime'], '%H:%M').time()
        if now.time().hour == due_time.hour and now.time().minute == due_time.minute:
            if not last_run_dt or last_run_dt.date() < now.date():
                return True
    elif scan_type == 'weekly':
        # Run on specified days at scan['weeklyTime']
        # Convert day names to weekday numbers
        day_name_to_number = {
            'Mon': '0',
            'Tue': '1',
            'Wed': '2',
            'Thu': '3',
            'Fri': '4',
            'Sat': '5',
            'Sun': '6'
        }
        
        # Check if today's weekday is in the selected days
        today_weekday = str(now.weekday())
        selected_days = scan.get('weeklyDays', [])
        
        # Convert day names to numbers if needed
        numeric_days = []
        for day in selected_days:
            if day in day_name_to_number:
                numeric_days.append(day_name_to_number[day])
            else:
                numeric_days.append(day)  # Already a number string
        
        if today_weekday in numeric_days:
            due_time = datetime.strptime(scan['weeklyTime'], '%H:%M').time()
            if now.time().hour == due_time.hour and now.time().minute == due_time.minute:
                if not last_run_dt or last_run_dt.date() < now.date():
                    return True
    elif scan_type == 'monthly':
        # Run on specified days of month at scan['monthlyTime']
        if now.day in scan.get('monthlyDays', []):
            due_time = datetime.strptime(scan['monthlyTime'], '%H:%M').time()
            if now.time().hour == due_time.hour and now.time().minute == due_time.minute:
                if not last_run_dt or last_run_dt.date() < now.date():
                    return True
    elif scan_type == 'custom':
        # Run once at scan['customTime']
        custom_time = datetime.fromisoformat(scan['customTime'])
        if now >= custom_time and (not last_run_dt):
            return True
    return False

def run_scheduled_scans():
    print("[Scheduler] Started background scheduled scan runner.")
    
    # Import dependencies here to avoid circular imports
    try:
        from app import scan_all
        scan_all_available = True
    except ImportError as e:
        print(f"[Scheduler] Error importing scan_all from app: {e}")
        scan_all_available = False
    
    # Import the report summarizer
    global SUMMARIZER_AVAILABLE
    try:
        from utils.report_summarizer import process_scan_reports
        SUMMARIZER_AVAILABLE = True
        print("[Scheduler] Report summarizer loaded successfully")
    except ImportError as e:
        print(f"[Scheduler] Report summarizer not available: {e}")
        SUMMARIZER_AVAILABLE = False
    
    # Import the CVE news scheduler
    global CVE_SCHEDULER_AVAILABLE
    try:
        from utils.cve_scheduler import run_cve_update
        CVE_SCHEDULER_AVAILABLE = True
        print("[Scheduler] CVE news scheduler loaded successfully")
    except ImportError as e:
        print(f"[Scheduler] CVE news scheduler not available: {e}")
        CVE_SCHEDULER_AVAILABLE = False
    
    if not scan_all_available:
        print("[Scheduler] Cannot run scheduled scans because scan_all function is not available")
        return
    
    while True:
        try:
            scans = load_scheduled_scans()
            changed = False
            for scan in scans:
                try:
                    if is_due(scan):
                        print(f"[Scheduler] Running scheduled scan for {scan['url']} (type: {scan['type']})")
                        # Run the scan (store results in structured folder)
                        try:
                            # Use the scan's ID for file naming
                            scan_id = str(scan.get('id', 'unknown'))
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            
                            # Run the scan with the scan_id and type='scheduled'
                            results = scan_all(scan['url'], sid=None, scan_type='scheduled', scan_id=scan_id)
                            
                            # Store report paths in the scan record
                            scan['last_run'] = datetime.now().isoformat()
                            scan['last_report'] = results.get('report_path', '')
                            scan['last_zap_report'] = results.get('zap_report_path', '')
                            scan['last_scan_id'] = scan_id
                            scan['last_timestamp'] = timestamp
                            
                            print(f"[Scheduler] Scan completed and saved to {results.get('report_path', 'unknown')}")
                            
                            # Dynamically wait for ZAP report to be fully written and available
                            print(f"[Scheduler] Waiting for ZAP report to be fully processed...")
                            
                            # Get the ZAP report path
                            zap_report_path = results.get('zap_report_path', '')
                            
                            # Define a function to check if the report is ready and valid
                            def is_report_ready(report_path):
                                if not os.path.exists(report_path):
                                    return False
                                
                                # Check if file has content and is not being written to
                                file_size = os.path.getsize(report_path)
                                if file_size == 0:
                                    return False
                                
                                # Check if file size is stable (not being written to)
                                time.sleep(2)  # Brief pause
                                new_size = os.path.getsize(report_path)
                                if file_size != new_size:
                                    return False
                                
                                # Verify the report is from the current scan by checking timestamp
                                try:
                                    # Get file modification time
                                    file_mtime = os.path.getmtime(report_path)
                                    file_time = datetime.fromtimestamp(file_mtime)
                                    
                                    # Get current scan start time
                                    current_time = datetime.now()
                                    scan_start_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                                    
                                    # Calculate time difference in minutes
                                    time_diff = (current_time - scan_start_time).total_seconds() / 60
                                    
                                    # Report should be newer than scan start time and within reasonable timeframe
                                    if file_time < scan_start_time:
                                        print(f"[Scheduler] ZAP report is older than current scan start time")
                                        return False
                                    
                                    print(f"[Scheduler] ZAP report time: {file_time}, Scan start time: {scan_start_time}")
                                    print(f"[Scheduler] Time difference: {time_diff:.2f} minutes")
                                    
                                    return True
                                except Exception as e:
                                    print(f"[Scheduler] Error verifying report timestamp: {e}")
                                    return False
                            
                            # Poll for report readiness with timeout
                            max_wait_time = 600  # Maximum wait time in seconds (10 minutes)
                            poll_interval = 5    # Check every 5 seconds
                            wait_time = 0
                            
                            while wait_time < max_wait_time:
                                if is_report_ready(zap_report_path):
                                    print(f"[Scheduler] ZAP report is ready at {zap_report_path}")
                                    break
                                
                                time.sleep(poll_interval)
                                wait_time += poll_interval
                                print(f"[Scheduler] Still waiting for ZAP report... ({wait_time}s elapsed)")
                            
                            if wait_time >= max_wait_time:
                                print(f"[Scheduler] Warning: Timed out waiting for ZAP report after {max_wait_time}s")
                                continue  # Skip report summarization if timeout occurs
                            
                            # Send reports to Gemini for summarization and then to Telegram
                            if SUMMARIZER_AVAILABLE:
                                try:
                                    print(f"[Scheduler] Summarizing reports for {scan['url']}...")
                                    summary_result = process_scan_reports(
                                        scan_report_path=results.get('report_path', ''),
                                        zap_report_path=results.get('zap_report_path', ''),
                                        url=scan['url'],
                                        scan_id=scan_id
                                    )
                                    if summary_result.get('success'):
                                        print(f"[Scheduler] Summary sent to Telegram successfully")
                                    else:
                                        print(f"[Scheduler] Failed to send summary to Telegram")
                                except Exception as e:
                                    print(f"[Scheduler] Error summarizing reports: {e}")
                                    # Continue execution even if summarization fails
                        except Exception as e:
                            print(f"[Scheduler] Error running scan for {scan['url']}: {e}")
                            scan['last_run'] = datetime.now().isoformat()
                            scan['last_error'] = str(e)
                        changed = True
                except Exception as e:
                    print(f"[Scheduler] Error processing scan {scan.get('id', 'unknown')}: {e}")
            
            if changed:
                save_scheduled_scans(scans)
            
            # Check for CVE updates
            if CVE_SCHEDULER_AVAILABLE:
                try:
                    cve_result = run_cve_update()
                    if cve_result.get('success'):
                        print(f"[Scheduler] CVE update completed successfully")
                except Exception as e:
                    print(f"[Scheduler] Error running CVE update: {e}")
        except Exception as e:
            print(f"[Scheduler] Error in scheduler main loop: {e}")
        
        # Sleep for 60 seconds before checking again
        time.sleep(60)

if __name__ == "__main__":
    run_scheduled_scans()
