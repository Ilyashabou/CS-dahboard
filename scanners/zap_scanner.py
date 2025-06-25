"""
OWASP ZAP Deep Scanner module (runs ZAP in WSL Ubuntu).
"""
import os
import subprocess
from typing import Dict, Any

def run_zap_scan(url: str, output_html: str = "results/zap_report.html", progress_hook=None) -> Dict[str, Any]:
    """
    Run OWASP ZAP deep scan using WSL Ubuntu and save the report as HTML.
    Streams output live to the console or via progress_hook.

    Args:
        url: The target URL to scan.
        output_html: The output HTML report path (relative to project root).
        progress_hook: Optional function(line:str) to call for each output line.

    Returns:
        Dict with scan status and report location.
    """
    import sys
    import shutil
    
    # Create a temporary output path for ZAP (it has issues with certain paths)
    temp_output = "ZAP_2.16.1/results/temp_zap_report.html"
    
    # Ensure the ZAP results directory exists
    os.makedirs(os.path.dirname(os.path.abspath(temp_output)), exist_ok=True)
    
    # Ensure the final output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_html)), exist_ok=True)
    
    # Log the output paths for debugging
    if progress_hook:
        progress_hook(f"[Scheduler] Saving ZAP report to: {output_html}")
    else:
        print(f"Saving ZAP report to: {output_html}")
    
    zap_dir = "/mnt/c/Users/ILYAS/OneDrive/Bureau/cybersecurity_dashboard/ZAP_2.16.1"
    zap_cmd = (
        f"cd {zap_dir} && ./zap.sh -cmd -quickurl {url} -quickprogress -quickout results/temp_zap_report.html"
    )
    try:
        # Use Popen to stream output
        process = subprocess.Popen(
            ["wsl", "-d", "Ubuntu", "--", "bash", "-c", zap_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        full_output = ""
        # Print each line as it arrives or send to hook
        for line in process.stdout:
            if progress_hook:
                progress_hook(line)
            else:
                print(line, end="")
                sys.stdout.flush()
            full_output += line
        process.wait()
        
        # Copy the report from the temp location to the final destination
        temp_path = os.path.join(os.getcwd(), "ZAP_2.16.1", "results", "temp_zap_report.html")
        if os.path.exists(temp_path):
            try:
                shutil.copy2(temp_path, output_html)
                if progress_hook:
                    progress_hook(f"[Scheduler] Scan completed and saved to {os.path.basename(output_html)}")
                else:
                    print(f"Scan completed and saved to {output_html}")
            except Exception as copy_error:
                if progress_hook:
                    progress_hook(f"[Scheduler] Error copying ZAP report: {str(copy_error)}")
                else:
                    print(f"Error copying ZAP report: {str(copy_error)}")
        
        if process.returncode == 0 and os.path.exists(output_html):
            return {
                "status": "success",
                "details": {
                    "message": f"ZAP scan completed. Report saved to {output_html}",
                    "report_path": output_html,
                    "stdout": full_output
                }
            }
        else:
            return {
                "status": "error",
                "details": {
                    "message": f"ZAP scan failed (exit code {process.returncode}) or report not found",
                    "stdout": full_output
                }
            }
    except Exception as e:
        return {
            "status": "error",
            "details": {
                "message": f"Exception running ZAP scan: {str(e)}"
            }
        }

class ZAPScanner:
    """
    Wrapper class for OWASP ZAP deep scan.
    """
    def scan(self, url: str, output_html: str = "results/zap_report.html", progress_hook=None) -> Dict[str, Any]:
        return run_zap_scan(url, output_html, progress_hook=progress_hook)
