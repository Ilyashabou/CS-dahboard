import os
import threading
import re
import json
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from scanners.ssl_checker import SSLChecker
from scanners.nmap_scanner import NmapScanner
from scanners.darkweb_checker import DarkwebChecker
from scanners.zap_scanner import ZAPScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Helper to emit progress updates
class ProgressEmitter:
    def __init__(self, sid):
        self.sid = sid
    def emit(self, event, data):
        socketio.emit(event, data, room=self.sid)

def scan_all(url, sid, scan_type='manual', scan_id=None):
    emitter = ProgressEmitter(sid) if sid else None
    results = {}
    
    # Generate timestamp and scan ID
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if scan_type == 'manual':
        # For manual scans, generate a unique ID
        import uuid
        if not scan_id:
            scan_id = str(uuid.uuid4())[:8]
        report_dir = os.path.join("results", "manual")
    else:  # scheduled
        report_dir = os.path.join("results", "scheduled")
        if not scan_id:
            scan_id = 'unknown'
    
    # Create report directory
    os.makedirs(report_dir, exist_ok=True)
    
    # Define report filenames
    # Include URL in the metadata filename (sanitize it first)
    sanitized_url = re.sub(r'[^a-zA-Z0-9]', '_', url)[:30]  # Limit length and remove special chars
    metadata_filename = f"scan_{scan_id}_{timestamp}_{sanitized_url}_metadata.json"
    report_filename = f"scan_{scan_id}_{timestamp}_report.html"
    zap_report_filename = f"scan_{scan_id}_{timestamp}_zap_report.html"
    report_path = os.path.join(report_dir, report_filename)
    zap_report_path = os.path.join(report_dir, zap_report_filename)
    metadata_path = os.path.join(report_dir, metadata_filename)
    
    # Save metadata with URL and other info
    metadata = {
        "url": url,
        "scan_id": scan_id,
        "timestamp": timestamp,
        "scan_type": scan_type
    }
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    # SSL Scan
    if emitter: emitter.emit('progress', {'step': 'SSL Scan', 'status': 'running'})
    ssl_results = SSLChecker().scan(url)
    results['ssl'] = ssl_results
    if emitter: emitter.emit('progress', {'step': 'SSL Scan', 'status': 'done', 'result': ssl_results})

    # Port Scan
    if emitter: emitter.emit('progress', {'step': 'Port Scan', 'status': 'running'})
    nmap_results = NmapScanner().scan(url)
    results['ports'] = nmap_results
    if emitter: emitter.emit('progress', {'step': 'Port Scan', 'status': 'done', 'result': nmap_results})

    # Dark Web Scan
    if emitter: emitter.emit('progress', {'step': 'Dark Web Exposure', 'status': 'running'})
    darkweb_results = DarkwebChecker().scan(url)
    results['darkweb'] = darkweb_results
    if emitter: emitter.emit('progress', {'step': 'Dark Web Exposure', 'status': 'done', 'result': darkweb_results})

    # ZAP Scan (with live output)
    if emitter: emitter.emit('progress', {'step': 'ZAP Deep Scan', 'status': 'running'})
    def zap_progress_hook(line):
        if sid:
            socketio.emit('zap_output', {'line': line}, room=sid)
        else:
            print(f"[ZAP] {line.strip()}")
            
    zap_results = ZAPScanner().scan(url, output_html=zap_report_path, progress_hook=zap_progress_hook)
    results['zap'] = zap_results
    if emitter: emitter.emit('progress', {'step': 'ZAP Deep Scan', 'status': 'done', 'result': zap_results})

    # Render the combined HTML report
    from flask import render_template
    global app
    with app.app_context():
        html_report = render_template(
            "scan_report.html",
            ssl=results['ssl'],
            ports=results['ports'],
            darkweb=results['darkweb'],
            zap=results['zap'],
            scan_id=scan_id,
            timestamp=timestamp,
            url=url,
            scan_type=scan_type
        )
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    # Store the report paths in results
    results['report_path'] = report_path
    results['zap_report_path'] = zap_report_path
    results['scan_id'] = scan_id
    results['timestamp'] = timestamp

    # All done
    if emitter:
        emitter.emit('complete', {
            'ssl': results['ssl'],
            'ports': results['ports'],
            'darkweb': results['darkweb'],
            'scan_report_url': f'/scan_report/{scan_type}/{scan_id}/{timestamp}',
            'zap_report_url': f'/zap_report/{scan_type}/{scan_id}/{timestamp}'
        })
    
    return results

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/zap_report/<scan_type>/<scan_id>/<timestamp>")
def zap_report(scan_type, scan_id, timestamp):
    # Serve the ZAP HTML report directly
    from flask import send_file, abort, redirect, url_for
    from datetime import datetime
    
    # Check if the requested report exists
    report_filename = f"scan_{scan_id}_{timestamp}_zap_report.html"
    report_path = os.path.join(os.getcwd(), "results", scan_type, report_filename)
    
    if os.path.exists(report_path):
        # Check if the report is valid (not empty and from the current scan)
        try:
            file_size = os.path.getsize(report_path)
            if file_size == 0:
                # Report exists but is empty - scan might be in progress
                return render_template("report_pending.html", 
                                      message="ZAP scan is still in progress. Please check back later.")
            
            # Check if the report is from the current scan by comparing timestamps
            file_mtime = os.path.getmtime(report_path)
            file_time = datetime.fromtimestamp(file_mtime)
            scan_start_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
            
            # If report is older than scan start time, it's not the correct report
            if file_time < scan_start_time:
                return render_template("report_pending.html", 
                                      message="ZAP scan is still in progress. The current report is from a previous scan.")
            
            # Valid report, serve it
            return send_file(report_path)
        except Exception as e:
            print(f"Error checking ZAP report: {e}")
            # Continue to serve the file even if checks fail
            return send_file(report_path)
    else:
        # Fallback to old path for backward compatibility
        old_report_path = os.path.join(os.getcwd(), "ZAP_2.16.1", "results", "zap_report.html")
        if os.path.exists(old_report_path):
            return send_file(old_report_path)
        abort(404)

@app.route("/scan_report/<scan_type>/<scan_id>/<timestamp>")
def scan_report(scan_type, scan_id, timestamp):
    # Serve the combined scan HTML report
    from flask import send_file, abort
    from datetime import datetime
    
    report_filename = f"scan_{scan_id}_{timestamp}_report.html"
    report_path = os.path.join(os.getcwd(), "results", scan_type, report_filename)
    
    # Also check for the corresponding ZAP report to ensure it's complete
    zap_report_filename = f"scan_{scan_id}_{timestamp}_zap_report.html"
    zap_report_path = os.path.join(os.getcwd(), "results", scan_type, zap_report_filename)
    
    if os.path.exists(report_path):
        # Check if the ZAP report is also ready and valid
        if os.path.exists(zap_report_path):
            try:
                # Check if the ZAP report is valid (not empty and from the current scan)
                zap_file_size = os.path.getsize(zap_report_path)
                if zap_file_size == 0:
                    # ZAP report exists but is empty - scan might be in progress
                    return render_template("report_pending.html", 
                                          message="ZAP scan is still in progress. Please check back later.")
                
                # Check if the ZAP report is from the current scan by comparing timestamps
                zap_file_mtime = os.path.getmtime(zap_report_path)
                zap_file_time = datetime.fromtimestamp(zap_file_mtime)
                scan_start_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                
                # If ZAP report is older than scan start time, it's not the correct report
                if zap_file_time < scan_start_time:
                    return render_template("report_pending.html", 
                                          message="ZAP scan is still in progress. The current report is from a previous scan.")
            except Exception as e:
                print(f"Error checking ZAP report for scan report: {e}")
                # Continue to serve the file even if checks fail
        
        # Valid report, serve it
        return send_file(report_path)
    else:
        # Fallback to old path for backward compatibility
        old_report_path = os.path.join(os.getcwd(), "results", "scan_report.html")
        if os.path.exists(old_report_path):
            return send_file(old_report_path)
        abort(404)
        
# For backward compatibility
@app.route("/zap_report")
def legacy_zap_report():
    from flask import send_file, abort
    report_path = os.path.join(os.getcwd(), "ZAP_2.16.1", "results", "zap_report.html")
    if os.path.exists(report_path):
        return send_file(report_path)
    else:
        abort(404)

@app.route("/scan_report")
def legacy_scan_report():
    from flask import send_file, abort
    report_path = os.path.join(os.getcwd(), "results", "scan_report.html")
    if os.path.exists(report_path):
        return send_file(report_path)
    else:
        abort(404)

@socketio.on('start_scan')
def handle_start_scan(data):
    url = data.get('url')
    sid = request.sid
    scan_thread = threading.Thread(target=scan_all, args=(url, sid, 'manual'))
    scan_thread.start()
    emit('progress', {'step': 'Started', 'status': 'running'})

from flask import jsonify, request, abort
import json
import threading

SCHEDULED_SCANS_FILE = 'scheduled_scans.json'
scheduled_scans_lock = threading.Lock()

def load_scheduled_scans():
    with scheduled_scans_lock:
        try:
            with open(SCHEDULED_SCANS_FILE, 'r', encoding='utf-8') as f:
                scans = json.load(f)
                print(f"Loaded scheduled scans: {scans}")
                return scans
        except FileNotFoundError:
            print("scheduled_scans.json not found, creating new file.")
            try:
                with open(SCHEDULED_SCANS_FILE, 'w', encoding='utf-8') as f:
                    json.dump([], f)
            except Exception as e:
                print(f"Error creating scheduled_scans.json: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error decoding scheduled_scans.json: {e}")
            return []

def save_scheduled_scans(scans):
    with scheduled_scans_lock:
        try:
            with open(SCHEDULED_SCANS_FILE, 'w', encoding='utf-8') as f:
                json.dump(scans, f, indent=2)
            print(f"Saved scheduled scans: {scans}")
        except Exception as e:
            print(f"Error saving scheduled_scans.json: {e}")

@app.route('/api/scheduled_scans', methods=['GET'])
def get_scheduled_scans():
    scans = load_scheduled_scans()
    print("GET /api/scheduled_scans called")
    return jsonify(scans)

@app.route('/api/scheduled_scans', methods=['POST'])
def add_scheduled_scan():
    print("POST /api/scheduled_scans called with:", request.json)
    scans = load_scheduled_scans()
    scan = request.json
    scan['id'] = max([s.get('id', 0) for s in scans] + [0]) + 1
    scans.append(scan)
    save_scheduled_scans(scans)
    return jsonify(scan), 201

@app.route('/api/scheduled_scans/<int:scan_id>', methods=['PUT'])
def update_scheduled_scan(scan_id):
    print(f"PUT /api/scheduled_scans/{scan_id} called with:", request.json)
    scans = load_scheduled_scans()
    for i, scan in enumerate(scans):
        if scan.get('id') == scan_id:
            scans[i] = request.json
            scans[i]['id'] = scan_id
            save_scheduled_scans(scans)
            return jsonify(scans[i])
    print(f"Scan with id {scan_id} not found for update.")
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scheduled_scans/<int:scan_id>', methods=['DELETE'])
def delete_scheduled_scan(scan_id):
    print(f"DELETE /api/scheduled_scans/{scan_id} called")
    scans = load_scheduled_scans()
    new_scans = [scan for scan in scans if scan.get('id') != scan_id]
    if len(new_scans) == len(scans):
        print(f"Scan with id {scan_id} not found for delete.")
        return jsonify({'error': 'Scan not found'}), 404
    save_scheduled_scans(new_scans)
    return '', 204

def start_scheduler_thread():
    """Start the scheduler in a background thread"""
    try:
        # Import here to avoid circular imports
        from schedule_runner import run_scheduled_scans
        print("Starting scheduler thread for automatic scheduled scans...")
        scheduler_thread = threading.Thread(target=run_scheduled_scans, daemon=True)
        scheduler_thread.start()
        return scheduler_thread
    except ImportError as e:
        print(f"Warning: Could not import schedule_runner: {e}")
        print("Scheduled scans will not run automatically.")
    except Exception as e:
        print(f"Error starting scheduler thread: {e}")
    return None

# New API endpoints for manual scan history
@app.route('/api/manual_scans', methods=['GET'])
def get_manual_scans():
    """Get list of all manual scans"""
    manual_scans = []
    manual_dir = os.path.join(os.getcwd(), "results", "manual")
    
    if os.path.exists(manual_dir):
        files = os.listdir(manual_dir)
        report_pattern = re.compile(r'scan_([a-zA-Z0-9]+)_(\d{8}_\d{6})_report\.html')
        metadata_pattern = re.compile(r'scan_([a-zA-Z0-9]+)_(\d{8}_\d{6})_.*_metadata\.json')
        
        # First collect all metadata files
        metadata_files = {}
        for file in files:
            metadata_match = metadata_pattern.match(file)
            if metadata_match:
                scan_id = metadata_match.group(1)
                timestamp = metadata_match.group(2)
                key = f"{scan_id}_{timestamp}"
                metadata_files[key] = os.path.join(manual_dir, file)
        
        # Then process report files
        for file in files:
            match = report_pattern.match(file)
            if match:
                scan_id = match.group(1)
                timestamp = match.group(2)
                key = f"{scan_id}_{timestamp}"
                
                # Check if ZAP report exists
                zap_report = f"scan_{scan_id}_{timestamp}_zap_report.html"
                has_zap_report = zap_report in files
                
                # Get URL from metadata if available
                url = "Unknown Target"
                if key in metadata_files:
                    try:
                        with open(metadata_files[key], 'r', encoding='utf-8') as f:
                            metadata = json.load(f)
                            url = metadata.get('url', "Unknown Target")
                    except Exception as e:
                        print(f"Error reading metadata {metadata_files[key]}: {e}")
                else:
                    # Fall back to extracting from HTML if no metadata
                    try:
                        report_path = os.path.join(manual_dir, file)
                        with open(report_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            url_match = re.search(r'<h1[^>]*>Scan Report for ([^<]+)</h1>', content)
                            if url_match:
                                url = url_match.group(1)
                    except Exception as e:
                        print(f"Error reading report {file}: {e}")
                
                # Format timestamp for display
                display_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[9:11]}:{timestamp[11:13]}:{timestamp[13:15]}"
                
                manual_scans.append({
                    'id': scan_id,
                    'timestamp': timestamp,
                    'display_time': display_time,
                    'url': url,
                    'report_url': f'/scan_report/manual/{scan_id}/{timestamp}',
                    'zap_report_url': f'/zap_report/manual/{scan_id}/{timestamp}' if has_zap_report else None
                })
    
    # Sort by timestamp (newest first)
    manual_scans.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(manual_scans)

@app.route('/api/manual_scans/<scan_id>/<timestamp>', methods=['DELETE'])
def delete_manual_scan(scan_id, timestamp):
    """Delete a specific manual scan"""
    manual_dir = os.path.join(os.getcwd(), "results", "manual")
    report_file = f"scan_{scan_id}_{timestamp}_report.html"
    zap_report_file = f"scan_{scan_id}_{timestamp}_zap_report.html"
    
    success = False
    
    # Delete report file if exists
    report_path = os.path.join(manual_dir, report_file)
    if os.path.exists(report_path):
        try:
            os.remove(report_path)
            success = True
        except Exception as e:
            print(f"Error deleting report {report_path}: {e}")
    
    # Delete ZAP report file if exists
    zap_report_path = os.path.join(manual_dir, zap_report_file)
    if os.path.exists(zap_report_path):
        try:
            os.remove(zap_report_path)
            success = True
        except Exception as e:
            print(f"Error deleting ZAP report {zap_report_path}: {e}")
    
    if success:
        return '', 204
    else:
        return jsonify({'error': 'Scan not found or could not be deleted'}), 404

@app.route('/api/manual_scans', methods=['DELETE'])
def delete_all_manual_scans():
    """Delete all manual scans"""
    manual_dir = os.path.join(os.getcwd(), "results", "manual")
    
    if os.path.exists(manual_dir):
        files = os.listdir(manual_dir)
        deleted_count = 0
        
        for file in files:
            if file.endswith('.html'):
                try:
                    os.remove(os.path.join(manual_dir, file))
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting file {file}: {e}")
        
        return jsonify({'deleted_count': deleted_count}), 200
    
    return jsonify({'error': 'Manual scans directory not found'}), 404

# CVE News API Routes
@app.route('/api/cve_schedule', methods=['GET'])
def get_cve_schedule():
    """Get the current CVE news schedule settings"""
    try:
        from utils.cve_scheduler import load_cve_schedule
        schedule = load_cve_schedule()
        return jsonify(schedule)
    except ImportError:
        return jsonify({'error': 'CVE scheduler module not available'}), 500
    except Exception as e:
        return jsonify({'error': f'Error loading CVE schedule: {str(e)}'}), 500

@app.route('/api/cve_schedule', methods=['POST'])
def update_cve_schedule():
    """Update the CVE news schedule settings"""
    try:
        from utils.cve_scheduler import update_cve_schedule
        
        data = request.json
        enabled = data.get('enabled', False)
        time = data.get('time', '08:00')
        days_back = data.get('days_back', 1)
        
        # Validate time format
        try:
            from datetime import datetime
            datetime.strptime(time, '%H:%M')
        except ValueError:
            return jsonify({'error': 'Invalid time format. Use HH:MM format.'}), 400
        
        # Validate days_back
        try:
            days_back = int(days_back)
            if days_back < 1 or days_back > 30:
                return jsonify({'error': 'Days back must be between 1 and 30.'}), 400
        except ValueError:
            return jsonify({'error': 'Days back must be a number.'}), 400
        
        success = update_cve_schedule(enabled, time, days_back)
        if success:
            return jsonify({'success': True, 'message': 'CVE schedule updated successfully'})
        else:
            return jsonify({'error': 'Failed to update CVE schedule'}), 500
    except ImportError:
        return jsonify({'error': 'CVE scheduler module not available'}), 500
    except Exception as e:
        return jsonify({'error': f'Error updating CVE schedule: {str(e)}'}), 500

@app.route('/api/cve_news', methods=['GET'])
def get_cve_news():
    """Get the latest CVE news status (now only sent to Telegram)"""
    try:
        # Check if days_back parameter is provided
        days_back = request.args.get('days_back')
        
        # If days_back is provided, trigger a Telegram update
        if days_back:
            try:
                days_back = int(days_back)
                if days_back < 1 or days_back > 30:
                    return jsonify({'error': 'Days back must be between 1 and 30.'}), 400
                    
                # Import here to avoid circular imports
                from utils.cve_news_service import process_daily_cves
                from datetime import datetime
                
                # Process CVEs and send to Telegram
                result = process_daily_cves(days_back)
                
                # Return status message
                return jsonify({
                    'timestamp': int(datetime.now().timestamp()),
                    'message': 'CVE updates sent to Telegram. Check your Telegram for the latest security alerts.',
                    'days_back': days_back,
                    'cve_count': result.get('cve_count', 0)
                })
            except ValueError:
                return jsonify({'error': 'Days back must be a number.'}), 400
            except Exception as e:
                return jsonify({'error': f'Error processing CVE data: {str(e)}'}), 500
        
        # If no days_back parameter, return status from cache
        if os.path.exists('news_log.json'):
            with open('news_log.json', 'r', encoding='utf-8') as f:
                news_cache = json.load(f)
                
            # Return the most recent entry
            if news_cache:
                latest_news = news_cache[-1]  # Get the last entry
                # Override with standard message
                latest_news['message'] = 'CVE updates are now sent directly to Telegram. Check your Telegram for the latest security alerts.'
                if 'summary' in latest_news:
                    del latest_news['summary']
                if 'cves' in latest_news:
                    del latest_news['cves']
                return jsonify(latest_news)
            else:
                return jsonify({'message': 'No CVE news available yet'})
        else:
            return jsonify({'message': 'No CVE news available yet'})
    except Exception as e:
        return jsonify({'error': f'Error loading CVE news: {str(e)}'}), 500

@app.route('/api/cve_news/run', methods=['POST'])
def run_cve_news():
    """Manually trigger a CVE news update to Telegram"""
    try:
        from utils.cve_news_service import process_daily_cves
        
        data = request.json
        days_back = data.get('days_back', 1)
        
        # Validate days_back
        try:
            days_back = int(days_back)
            if days_back < 1 or days_back > 30:
                return jsonify({'error': 'Days back must be between 1 and 30.'}), 400
        except ValueError:
            return jsonify({'error': 'Days back must be a number.'}), 400
        
        # Run in a separate thread to avoid blocking the request
        def run_update():
            try:
                process_daily_cves(days_back)
            except Exception as e:
                print(f"Error running CVE update: {e}")
        
        thread = threading.Thread(target=run_update)
        thread.start()
        
        return jsonify({'success': True, 'message': 'CVE news update started. Check your Telegram for the latest security alerts.'})
    except ImportError:
        return jsonify({'error': 'CVE news service module not available'}), 500
    except Exception as e:
        return jsonify({'error': f'Error starting CVE news update: {str(e)}'}), 500

if __name__ == "__main__":
    # Ensure results directories exist
    os.makedirs('results/manual', exist_ok=True)
    os.makedirs('results/scheduled', exist_ok=True)
    
    # Start the scheduler in a background thread
    scheduler_thread = start_scheduler_thread()
    
    # Run the Flask app
    socketio.run(app, host="0.0.0.0", port=3000, debug=True)
