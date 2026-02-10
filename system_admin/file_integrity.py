"""
file_integrity.py
Monitors file integrity using SHA-256 hashing to detect unauthorized changes.

Usage:
    python system_admin/file_integrity.py --baseline <folder>   # Create baseline
    python system_admin/file_integrity.py --check <folder>      # Check against baseline
"""

import hashlib
import json
import sys
from pathlib import Path
from datetime import datetime
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger


# Configuration
BASELINE_FILE = "integrity_baseline.json"
LOG_FILE = "file_integrity.log"


def calculate_file_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        file_path: Path object pointing to the file
    
    Returns:
        str: Hexadecimal hash string
    """
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None


def scan_directory(directory, logger, recursive=True):
    """
    Scan directory and create hash inventory.
    
    Args:
        directory: Path to scan
        logger: Logger instance
        recursive: Whether to scan subdirectories
    
    Returns:
        dict: File paths mapped to their hashes and metadata
    """
    directory = Path(directory)
    inventory = {}
    
    if not directory.exists():
        logger.error(f"Directory does not exist: {directory}")
        return inventory
    
    # Get all files
    if recursive:
        files = directory.rglob("*")
    else:
        files = directory.glob("*")
    
    file_count = 0
    error_count = 0
    
    for file_path in files:
        if file_path.is_file():
            file_count += 1
            
            # Calculate hash
            file_hash = calculate_file_hash(file_path)
            
            if file_hash:
                # Store relative path for portability
                relative_path = str(file_path.relative_to(directory))
                
                inventory[relative_path] = {
                    "hash": file_hash,
                    "size": file_path.stat().st_size,
                    "modified": file_path.stat().st_mtime,
                    "scanned": datetime.now().isoformat()
                }
                
                logger.debug(f"Hashed: {relative_path}")
            else:
                error_count += 1
                logger.warning(f"Could not hash: {file_path}")
    
    logger.info(f"Scanned {file_count} files ({error_count} errors)")
    return inventory


def create_baseline(directory, logger, output_file=BASELINE_FILE):
    """
    Create a baseline hash inventory of a directory.
    
    Args:
        directory: Directory to baseline
        logger: Logger instance
        output_file: Where to save the baseline
    """
    logger.info(f"Creating baseline for: {directory}")
    
    inventory = scan_directory(directory, logger)
    
    if not inventory:
        logger.error("No files found or all files failed to hash")
        return False
    
    # Save baseline with metadata
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
    """
    Load baseline from file.
    
    Args:
        baseline_file: Path to baseline JSON
        logger: Logger instance
    
    Returns:
        dict: Baseline data or None if failed
    """
    try:
        with open(baseline_file, 'r') as f:
            data = json.load(f)
        
        logger.info(f"Loaded baseline from: {baseline_file}")
        logger.info(f"Baseline created: {data.get('created')}")
        logger.info(f"Baseline file count: {data.get('file_count')}")
        
        return data
        
    except FileNotFoundError:
        logger.error(f"Baseline file not found: {baseline_file}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid baseline file format: {e}")
        return None
    except Exception as e:
        logger.exception(f"Error loading baseline: {e}")
        return None


def compare_inventories(baseline, current, logger):
    """
    Compare current state against baseline.
    
    Args:
        baseline: Baseline inventory dict
        current: Current inventory dict
        logger: Logger instance
    
    Returns:
        dict: Changes detected (modified, added, deleted)
    """
    baseline_files = baseline.get("files", {})
    current_files = current
    
    changes = {
        "modified": [],
        "added": [],
        "deleted": [],
        "unchanged": 0
    }
    
    # Check for modifications and deletions
    for file_path, baseline_info in baseline_files.items():
        if file_path in current_files:
            # File exists - check if modified
            if current_files[file_path]["hash"] != baseline_info["hash"]:
                changes["modified"].append({
                    "path": file_path,
                    "baseline_hash": baseline_info["hash"],
                    "current_hash": current_files[file_path]["hash"]
                })
                logger.warning(f"MODIFIED: {file_path}")
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


def print_integrity_report(changes):
    """
    Print a formatted integrity check report.
    
    Args:
        changes: Dict containing detected changes
    """
    print("\n" + "=" * 70)
    print("FILE INTEGRITY CHECK REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    total_changes = (
        len(changes["modified"]) +
        len(changes["added"]) +
        len(changes["deleted"])
    )
    
    if total_changes == 0:
        print("\n✓ NO CHANGES DETECTED")
        print(f"  {changes['unchanged']} files verified - all match baseline")
    else:
        print(f"\n⚠️  {total_changes} CHANGE(S) DETECTED")
        
        if changes["modified"]:
            print(f"\nMODIFIED FILES ({len(changes['modified'])}):")
            for item in changes["modified"]:
                print(f"  - {item['path']}")
                print(f"    Baseline: {item['baseline_hash'][:16]}...")
                print(f"    Current:  {item['current_hash'][:16]}...")
        
        if changes["added"]:
            print(f"\nADDED FILES ({len(changes['added'])}):")
            for file_path in changes["added"]:
                print(f"  + {file_path}")
        
        if changes["deleted"]:
            print(f"\nDELETED FILES ({len(changes['deleted'])}):")
            for file_path in changes["deleted"]:
                print(f"  - {file_path}")
        
        print(f"\nUNCHANGED: {changes['unchanged']} files")
    
    print("\n" + "=" * 70 + "\n")


def check_integrity(directory, logger, baseline_file=BASELINE_FILE):
    """
    Check directory integrity against baseline.
    
    Args:
        directory: Directory to check
        logger: Logger instance
        baseline_file: Path to baseline file
    """
    logger.info(f"Checking integrity for: {directory}")
    
    # Load baseline
    baseline = load_baseline(baseline_file, logger)
    if not baseline:
        print("\n❌ ERROR: No baseline found. Create one first with --baseline")
        return False
    
    # Scan current state
    logger.info("Scanning current state...")
    current = scan_directory(directory, logger)
    
    if not current:
        logger.error("Failed to scan current directory")
        return False
    
    # Compare
    changes = compare_inventories(baseline, current, logger)
    
    # Print report
    print_integrity_report(changes)
    
    # Summary logging
    total_changes = (
        len(changes["modified"]) +
        len(changes["added"]) +
        len(changes["deleted"])
    )
    
    if total_changes > 0:
        logger.warning(f"Integrity check FAILED: {total_changes} changes detected")
        return False
    else:
        logger.info("Integrity check PASSED: No changes detected")
        return True


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor using SHA-256 hashing"
    )
    parser.add_argument(
        "--baseline",
        metavar="DIR",
        help="Create baseline for specified directory"
    )
    parser.add_argument(
        "--check",
        metavar="DIR",
        help="Check integrity of specified directory against baseline"
    )
    parser.add_argument(
        "--output",
        default=BASELINE_FILE,
        help=f"Baseline output file (default: {BASELINE_FILE})"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("File Integrity Monitor Started")
    logger.info("=" * 50)
    
    try:
        if args.baseline:
            # Create baseline mode
            success = create_baseline(args.baseline, logger, args.output)
            if success:
                print(f"\n✓ Baseline created successfully: {args.output}")
            else:
                print(f"\n❌ Failed to create baseline")
            
        elif args.check:
            # Check integrity mode
            check_integrity(args.check, logger, args.output)
            
        else:
            # No arguments provided
            parser.print_help()
            print("\nExample usage:")
            print("  Create baseline:  python system_admin/file_integrity.py --baseline ./test_folder")
            print("  Check integrity:  python system_admin/file_integrity.py --check ./test_folder")
        
        logger.info("File Integrity Monitor Completed")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check file_integrity.log for details.")


if __name__ == "__main__":
    main()
