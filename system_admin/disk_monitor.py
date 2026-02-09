"""
disk_monitor.py
Monitors disk usage across all drives and alerts if any drive exceeds threshold.

Usage:
    python system_admin/disk_monitor.py
"""

import shutil
import sys
from pathlib import Path
from datetime import datetime

# Add repo root to Python path BEFORE importing utils
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger


# Configuration
ALERT_THRESHOLD = 80  # Alert if disk usage exceeds this percentage
LOG_FILE = "disk_monitor.log"


def get_disk_usage(path):
    """Get disk usage statistics for a given path."""
    try:
        usage = shutil.disk_usage(path)
        
        total_gb = usage.total / (1024 ** 3)
        used_gb = usage.used / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        percent_used = (usage.used / usage.total) * 100
        
        return {
            "path": path,
            "total_gb": round(total_gb, 2),
            "used_gb": round(used_gb, 2),
            "free_gb": round(free_gb, 2),
            "percent_used": round(percent_used, 2),
            "status": "CRITICAL" if percent_used >= ALERT_THRESHOLD else "OK"
        }
    except Exception as e:
        return {
            "path": path,
            "error": str(e),
            "status": "ERROR"
        }


def get_windows_drives():
    """Get all available drive letters on Windows."""
    import string
    drives = []
    
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if Path(drive).exists():
            drives.append(drive)
    
    return drives


def get_drives():
    """Get all available drives based on operating system."""
    import platform
    
    if platform.system() == "Windows":
        return get_windows_drives()
    else:
        return ["/"]


def check_all_disks(logger):
    """Check disk usage for all available drives."""
    drives = get_drives()
    results = []
    
    logger.info(f"Scanning {len(drives)} drive(s)...")
    
    for drive in drives:
        logger.debug(f"Checking drive: {drive}")
        usage_info = get_disk_usage(drive)
        results.append(usage_info)
        
        if usage_info.get("status") == "ERROR":
            logger.error(f"Error checking {drive}: {usage_info.get('error')}")
        elif usage_info.get("status") == "CRITICAL":
            logger.warning(f"ALERT: {drive} is at {usage_info['percent_used']}% used")
        else:
            logger.info(f"OK: {drive} is at {usage_info['percent_used']}% used")
    
    return results


def print_summary(results):
    """Print a formatted summary of disk usage."""
    print("\n" + "=" * 70)
    print("DISK USAGE REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Alert Threshold: {ALERT_THRESHOLD}%")
    print("=" * 70)
    
    for disk in results:
        if disk.get("status") == "ERROR":
            print(f"\n{disk['path']}: ERROR - {disk.get('error')}")
            continue
        
        status_icon = "!" if disk["status"] == "CRITICAL" else "OK"
        print(f"\n[{status_icon}] Drive: {disk['path']}")
        print(f"    Total:  {disk['total_gb']:.2f} GB")
        print(f"    Used:   {disk['used_gb']:.2f} GB")
        print(f"    Free:   {disk['free_gb']:.2f} GB")
        print(f"    Usage:  {disk['percent_used']:.2f}%")
        print(f"    Status: {disk['status']}")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """Main execution function."""
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Disk Monitor Started")
    logger.info("=" * 50)
    
    try:
        results = check_all_disks(logger)
        print_summary(results)
        
        critical_drives = [d for d in results if d.get("status") == "CRITICAL"]
        
        if critical_drives:
            logger.warning(f"{len(critical_drives)} drive(s) exceed {ALERT_THRESHOLD}% threshold")
        else:
            logger.info("All drives are within acceptable usage limits")
        
        logger.info("Disk Monitor Completed Successfully")
        
    except KeyboardInterrupt:
        logger.warning("Monitoring cancelled by user")
        print("\nMonitoring cancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\nError: {e}")
        print("Check disk_monitor.log for details.")


if __name__ == "__main__":
    main()
