"""CVE News Scheduler - Integrates CVE news service with the scheduler system."""
import os
import json
import threading
from datetime import datetime
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cve_scheduler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cve_scheduler")

# Load environment variables
load_dotenv()

# Configuration file
CVE_SCHEDULE_FILE = 'cve_schedule.json'

# Lock for thread safety
lock = threading.Lock()

def load_cve_schedule():
    """Load the CVE schedule from file."""
    with lock:
        try:
            if os.path.exists(CVE_SCHEDULE_FILE):
                with open(CVE_SCHEDULE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {"enabled": False, "time": "08:00", "days_back": 1}
        except Exception as e:
            logger.error(f"Error loading CVE schedule: {str(e)}")
            return {"enabled": False, "time": "08:00", "days_back": 1}

def save_cve_schedule(schedule):
    """Save the CVE schedule to file."""
    with lock:
        try:
            with open(CVE_SCHEDULE_FILE, 'w', encoding='utf-8') as f:
                json.dump(schedule, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving CVE schedule: {str(e)}")
            return False

def update_cve_schedule(enabled, time, days_back=1):
    """Update the CVE schedule."""
    schedule = {
        "enabled": enabled,
        "time": time,
        "days_back": days_back,
        "last_run": None
    }
    return save_cve_schedule(schedule)

def is_cve_update_due():
    """Check if a CVE update is due."""
    schedule = load_cve_schedule()
    
    # If not enabled, not due
    if not schedule.get("enabled", False):
        return False
    
    now = datetime.now()
    scheduled_time = schedule.get("time", "08:00")
    
    # Parse the scheduled time
    try:
        due_time = datetime.strptime(scheduled_time, "%H:%M").time()
    except ValueError:
        logger.error(f"Invalid time format: {scheduled_time}")
        return False
    
    # Check if it's time to run
    if now.time().hour == due_time.hour and now.time().minute == due_time.minute:
        last_run = schedule.get("last_run")
        if last_run:
            last_run_dt = datetime.fromisoformat(last_run)
            if last_run_dt.date() >= now.date():
                # Already run today
                return False
        return True
    
    return False

def mark_cve_update_complete():
    """Mark the CVE update as complete."""
    schedule = load_cve_schedule()
    schedule["last_run"] = datetime.now().isoformat()
    return save_cve_schedule(schedule)

def run_cve_update():
    """Run the CVE update if it's due."""
    if is_cve_update_due():
        try:
            # Import here to avoid circular imports
            from utils.cve_news_service import process_daily_cves
            
            # Get days_back from schedule
            schedule = load_cve_schedule()
            days_back = schedule.get("days_back", 1)
            
            # Process CVEs
            logger.info(f"Running scheduled CVE update (looking back {days_back} days)")
            result = process_daily_cves(days_back)
            
            # Mark as complete
            mark_cve_update_complete()
            
            logger.info(f"CVE update completed: {result['success']}")
            return result
        except Exception as e:
            logger.error(f"Error running CVE update: {str(e)}")
            return {"success": False, "error": str(e)}
    
    return {"success": False, "message": "Not due for update"}

# For testing
if __name__ == "__main__":
    # Enable CVE updates at the current time for testing
    now = datetime.now()
    current_time = now.strftime("%H:%M")
    update_cve_schedule(True, current_time)
    
    # Run the update
    result = run_cve_update()
    print(json.dumps(result, indent=2))