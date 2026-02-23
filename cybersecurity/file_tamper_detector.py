"""
file_tamper_detector.py
Advanced file tampering detection with real-time monitoring and critical file tracking.

Usage:
    python cybersecurity/file_tamper_detector.py --baseline <folder>
    python cybersecurity/file_tamper_detector.py --check <folder>
    python cybersecurity/file_tamper_detector.py --watch <folder> --interval 10
    python cybersecurity/file_tamper_detector.py --critical
"""

import hashlib
import json
import sys
import time
from pathlib import Path
from datetime import datetime
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
BASELINE_FILE = "tamper_baseline.json"
LOG_FILE = "file_tamper_detector.log"
WATCH_INTERVAL = 10  # Seconds between checks in watch mode

# Critical system files (examples - adjust for your OS)
CRITICAL_FILES_WINDOWS = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\config\\SAM",
]

CRITICAL_FILES_LINUX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
]


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def get_file_metadata(file_path):
    """Get detailed file metadata."""
    try:
        stat = file_path.stat()
        return {
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "created": stat.st_ctime,
            "permissions": oct(stat.st_mode)[-3:],
        }
    except Exception:
        return None


def scan_directory(directory, logger, recursive=True):
    """Scan directory and create hash inventory with metadata."""
    directory = Path(directory)
    inventory = {}
    
    if not directory.exists():
        logger.error(f"Directory does not exist: {directory}")
        return inventory
    
    if recursive:
        files = directory.rglob("*")
    else:
        files = directory.glob("*")
    
    file_count = 0
    
    for file_path in files:
        if file_path.is_file():
            file_count += 1
            
            file_hash = calculate_file_hash(file_path)
            metadata = get_file_metadata(file_path)
            
            if file_hash and metadata:
                relative_path = str(file_path.relative_to(directory))
                
                inventory[relative_path] = {
                    "hash": file_hash,
                    "size": metadata["size"],
                    "modified": metadata["modified"],
                    "created": metadata["created"],
                    "permissions": metadata["permissions"],
                    "scanned": datetime.now().isoformat()
                }
                
                logger.debug(f"Scanned: {relative_path}")
    
    logger.info(f"Scanned {file_count} files")
    return inventory


def create_baseline(directory, logger, output_file=BASELINE_FILE):
    """Create baseline hash inventory."""
    logger.info(f"Creating baseline for: {directory}")
    
    inventory = scan_directory(directory, logger)
    
    if not inventory:
        logger.error("No files found")
        return False
    
    baseline_data = {
        "directory": str(directory),
        "created": datetime.now().isoformat(),
        "file_count": len(inventory),
        "files": inventory
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        logger.info(f"Baseline created: {output_file}")
        logger.info(f"Total files: {len(inventory)}")
        return True
        
    except Exception as e:
        logger.exception(f"Failed to save baseline: {e}")
        return False


def load_baseline(baseline_file, logger):
    """Load baseline from file."""
    try:
        with open(baseline_file, 'r') as f:
            data = json.load(f)
        
        logger.info(f"Loaded baseline: {baseline_file}")
        logger.info(f"Baseline created: {data.get('created')}")
        logger.info(f"Baseline file count: {data.get('file_count')}")
        
        return data
        
    except FileNotFoundError:
        logger.error(f"Baseline file not found: {baseline_file}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid baseline format: {e}")
        return None
    except Exception as e:
        logger.exception(f"Error loading baseline: {e}")
        return None


def compare_inventories(baseline, current, logger):
    """Compare current state against baseline with detailed analysis."""
    baseline_files = baseline.get("files", {})
    current_files = current
    
    changes = {
        "modified": [],
        "added": [],
        "deleted": [],
        "permission_changed": [],
        "size_changed": [],
        "unchanged": 0
    }
    
    # Check for modifications and deletions
    for file_path, baseline_info in baseline_files.items():
        if file_path in current_files:
            current_info = current_files[file_path]
            
            # Check hash
            if current_info["hash"] != baseline_info["hash"]:
                changes["modified"].append({
                    "path": file_path,
                    "baseline_hash": baseline_info["hash"],
                    "current_hash": current_info["hash"],
                    "baseline_modified": datetime.fromtimestamp(baseline_info["modified"]),
                    "current_modified": datetime.fromtimestamp(current_info["modified"])
                })
                logger.warning(f"MODIFIED: {file_path}")
            
            # Check permissions
            elif current_info["permissions"] != baseline_info["permissions"]:
                changes["permission_changed"].append({
                    "path": file_path,
                    "baseline_perm": baseline_info["permissions"],
                    "current_perm": current_info["permissions"]
                })
                logger.warning(f"PERMISSIONS CHANGED: {file_path}")
            
            # Check size (might indicate change even if hash same)
            elif current_info["size"] != baseline_info["size"]:
                changes["size_changed"].append({
                    "path": file_path,
                    "baseline_size": baseline_info["size"],
                    "current_size": current_info["size"]
                })
                logger.warning(f"SIZE CHANGED: {file_path}")
            
            else:
                changes["unchanged"] += 1
        else:
            # File was deleted
            changes["deleted"].append(file_path)
            logger.warning(f"DELETED: {file_path}")
    
    # Check for new files
    for file_path in current_files:
        if file_path not in baseline_files:
            changes["added"].append(file_path)
            logger.warning(f"ADDED: {file_path}")
    
    return changes


def print_tamper_report(changes, directory):
    """Print formatted tampering detection report."""
    print("\n" + "=" * 80)
    print("FILE TAMPERING DETECTION REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Directory: {directory}")
    print("=" * 80)
    
    total_changes = (
        len(changes["modified"]) +
        len(changes["added"]) +
        len(changes["deleted"]) +
        len(changes["permission_changed"]) +
        len(changes["size_changed"])
    )
    
    if total_changes == 0:
        print("\n✓ NO TAMPERING DETECTED")
        print(f"  {changes['unchanged']} files verified - all match baseline")
    else:
        print(f"\n⚠️  {total_changes} CHANGE(S) DETECTED")
        
        if changes["modified"]:
            print(f"\n🔴 CONTENT MODIFIED ({len(changes['modified'])} files)")
            for item in changes["modified"]:
                print(f"   File: {item['path']}")
                print(f"      Hash changed: {item['baseline_hash'][:16]}... → {item['current_hash'][:16]}...")
                print(f"      Time: {item['current_modified'].strftime('%Y-%m-%d %H:%M:%S')}")
        
        if changes["permission_changed"]:
            print(f"\n🟡 PERMISSIONS CHANGED ({len(changes['permission_changed'])} files)")
            for item in changes["permission_changed"]:
                print(f"   {item['path']}")
                print(f"      {item['baseline_perm']} → {item['current_perm']}")
        
        if changes["size_changed"]:
            print(f"\n🟡 SIZE CHANGED ({len(changes['size_changed'])} files)")
            for item in changes["size_changed"]:
                print(f"   {item['path']}")
                print(f"      {item['baseline_size']} bytes → {item['current_size']} bytes")
        
        if changes["added"]:
            print(f"\n🟢 FILES ADDED ({len(changes['added'])})")
            for file_path in changes["added"][:10]:
                print(f"   + {file_path}")
            if len(changes["added"]) > 10:
                print(f"   ... and {len(changes['added']) - 10} more")
        
        if changes["deleted"]:
            print(f"\n🔴 FILES DELETED ({len(changes['deleted'])})")
            for file_path in changes["deleted"][:10]:
                print(f"   - {file_path}")
            if len(changes["deleted"]) > 10:
                print(f"   ... and {len(changes['deleted']) - 10} more")
        
        print(f"\n✓ UNCHANGED: {changes['unchanged']} files")
    
    print("\n" + "=" * 80 + "\n")


def check_integrity(directory, logger, baseline_file=BASELINE_FILE):
    """Check directory integrity against baseline."""
    logger.info(f"Checking integrity for: {directory}")
    
    baseline = load_baseline(baseline_file, logger)
    if not baseline:
        print("\n❌ ERROR: No baseline found. Create one first with --baseline")
        return False, None
    
    logger.info("Scanning current state...")
    current = scan_directory(directory, logger)
    
    if not current:
        logger.error("Failed to scan directory")
        return False, None
    
    changes = compare_inventories(baseline, current, logger)
    
    print_tamper_report(changes, directory)
    
    total_changes = (
        len(changes["modified"]) +
        len(changes["added"]) +
        len(changes["deleted"]) +
        len(changes["permission_changed"]) +
        len(changes["size_changed"])
    )
    
    if total_changes > 0:
        logger.warning(f"Tampering detected: {total_changes} changes")
        return False, changes
    else:
        logger.info("Integrity check passed")
        return True, changes


def watch_directory(directory, logger, baseline_file=BASELINE_FILE, interval=WATCH_INTERVAL):
    """Continuously monitor directory for tampering."""
    logger.info(f"Starting watch mode on: {directory}")
    logger.info(f"Check interval: {interval} seconds")
    print(f"\n👁️  WATCH MODE ACTIVE")
    print(f"   Directory: {directory}")
    print(f"   Interval: {interval} seconds")
    print(f"   Press Ctrl+C to stop\n")
    
    check_count = 0
    alert_count = 0
    
    try:
        while True:
            check_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            print(f"[{timestamp}] Check #{check_count}...", end=" ", flush=True)
            
            passed, changes = check_integrity(directory, logger, baseline_file)
            
            if passed:
                print("✓ OK")
            else:
                alert_count += 1
                print(f"⚠️  ALERT - {sum(len(v) if isinstance(v, list) else 0 for v in changes.values() if isinstance(v, list))} changes detected")
                logger.warning(f"Watch alert #{alert_count}: Changes detected")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n\n👁️  Watch mode stopped")
        print(f"   Total checks: {check_count}")
        print(f"   Alerts: {alert_count}\n")
        logger.info(f"Watch mode stopped - {check_count} checks, {alert_count} alerts")


def check_critical_files(logger):
    """Check critical system files for tampering."""
    import platform
    
    if platform.system() == "Windows":
        critical_files = CRITICAL_FILES_WINDOWS
    else:
        critical_files = CRITICAL_FILES_LINUX
    
    print("\n" + "=" * 80)
    print("CRITICAL SYSTEM FILE CHECK")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    checked = 0
    missing = 0
    
    for file_path_str in critical_files:
        file_path = Path(file_path_str)
        
        if file_path.exists():
            file_hash = calculate_file_hash(file_path)
            metadata = get_file_metadata(file_path)
            
            print(f"\n✓ {file_path}")
            print(f"   Hash: {file_hash[:32]}...")
            print(f"   Size: {metadata['size']} bytes")
            print(f"   Permissions: {metadata['permissions']}")
            
            checked += 1
            logger.info(f"Critical file OK: {file_path}")
        else:
            print(f"\n❌ MISSING: {file_path}")
            missing += 1
            logger.warning(f"Critical file missing: {file_path}")
    
    print(f"\n📊 Summary: {checked} checked, {missing} missing")
    print("=" * 80 + "\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="File Tampering Detector - Advanced integrity monitoring"
    )
    parser.add_argument("--baseline", metavar="DIR", help="Create baseline for directory")
    parser.add_argument("--check", metavar="DIR", help="Check directory against baseline")
    parser.add_argument("--watch", metavar="DIR", help="Continuously monitor directory")
    parser.add_argument("--critical", action="store_true", help="Check critical system files")
    parser.add_argument("--interval", type=int, default=WATCH_INTERVAL, help="Watch interval in seconds")
    parser.add_argument("--baseline-file", default=BASELINE_FILE, help="Baseline file path")
    
    args = parser.parse_args()
    
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("File Tamper Detector Started")
    logger.info("=" * 50)
    
    try:
        if args.baseline:
            success = create_baseline(args.baseline, logger, args.baseline_file)
            if success:
                print(f"\n✓ Baseline created: {args.baseline_file}")
        
        elif args.check:
            check_integrity(args.check, logger, args.baseline_file)
        
        elif args.watch:
            watch_directory(args.watch, logger, args.baseline_file, args.interval)
        
        elif args.critical:
            check_critical_files(logger)
        
        else:
            parser.print_help()
            print("\nExample usage:")
            print("  Create baseline:  python cybersecurity/file_tamper_detector.py --baseline ./important_files")
            print("  Check integrity:  python cybersecurity/file_tamper_detector.py --check ./important_files")
            print("  Watch mode:       python cybersecurity/file_tamper_detector.py --watch ./important_files --interval 5")
            print("  Critical files:   python cybersecurity/file_tamper_detector.py --critical")
        
        logger.info("File Tamper Detector Completed")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check file_tamper_detector.log for details.")


if __name__ == "__main__":
    main()
