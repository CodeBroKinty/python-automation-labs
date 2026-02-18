"""
log_parser.py
Parses authentication logs to detect failed login attempts and suspicious activity.

Usage:
    python cybersecurity/log_parser.py --file <log_file>
    python cybersecurity/log_parser.py --sample    # Generate and parse sample log
"""

import sys
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "log_parser.log"
FAILED_LOGIN_THRESHOLD = 5  # Alert if user has this many failed logins


def generate_sample_log():
    """Generate a sample authentication log file for testing."""
    sample_log = """
Jan 15 10:23:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:47 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:49 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 10:24:01 server sshd[1237]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:03 server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:05 server sshd[1239]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:07 server sshd[1240]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:09 server sshd[1241]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:11 server sshd[1242]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:25:30 server sshd[1243]: Accepted password for user1 from 192.168.1.50 port 22 ssh2
Jan 15 10:26:45 server sshd[1244]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2
Jan 15 10:26:47 server sshd[1245]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2
Jan 15 10:26:49 server sshd[1246]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2
Jan 15 10:27:10 server sshd[1247]: Failed password for admin from 203.0.113.50 port 22 ssh2
Jan 15 10:27:12 server sshd[1248]: Failed password for admin from 203.0.113.50 port 22 ssh2
Jan 15 10:28:00 server sshd[1249]: Accepted password for admin from 192.168.1.25 port 22 ssh2
Jan 15 10:29:15 server sshd[1250]: Failed password for backup from 192.168.1.100 port 22 ssh2
Jan 15 10:29:17 server sshd[1251]: Failed password for backup from 192.168.1.100 port 22 ssh2
Jan 15 10:29:19 server sshd[1252]: Failed password for backup from 192.168.1.100 port 22 ssh2
Jan 15 10:29:21 server sshd[1253]: Failed password for backup from 192.168.1.100 port 22 ssh2
""".strip()
    
    sample_file = Path("sample_auth.log")
    sample_file.write_text(sample_log)
    return sample_file


def parse_auth_log_line(line):
    """
    Parse a single authentication log line.
    
    Args:
        line: Log line string
    
    Returns:
        dict: Parsed information or None if line doesn't match
    """
    # Linux SSH log pattern
    # Example: Jan 15 10:23:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted) password for (invalid user )?(\S+) from (\S+)'
    
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        status = match.group(2)
        invalid_prefix = match.group(3)
        username = match.group(4)
        ip_address = match.group(5)
        
        # Add current year to timestamp (logs often don't include year)
        current_year = datetime.now().year
        try:
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = None
        
        return {
            "timestamp": timestamp,
            "status": status,
            "username": username,
            "ip_address": ip_address,
            "is_invalid_user": bool(invalid_prefix),
            "raw_line": line.strip()
        }
    
    return None


def parse_log_file(log_file_path, logger):
    """
    Parse an authentication log file.
    
    Args:
        log_file_path: Path to log file
        logger: Logger instance
    
    Returns:
        list: Parsed log entries
    """
    log_file = Path(log_file_path)
    
    if not log_file.exists():
        logger.error(f"Log file not found: {log_file_path}")
        return []
    
    parsed_entries = []
    line_count = 0
    parsed_count = 0
    
    logger.info(f"Parsing log file: {log_file_path}")
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                entry = parse_auth_log_line(line)
                
                if entry:
                    parsed_entries.append(entry)
                    parsed_count += 1
                    logger.debug(f"Parsed: {entry['status']} login for {entry['username']} from {entry['ip_address']}")
        
        logger.info(f"Processed {line_count} lines, parsed {parsed_count} authentication events")
        
    except Exception as e:
        logger.exception(f"Error reading log file: {e}")
        return []
    
    return parsed_entries


def analyze_failed_logins(entries, logger, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Analyze failed login attempts.
    
    Args:
        entries: List of parsed log entries
        logger: Logger instance
    
    Returns:
        dict: Analysis results
    """
    # Count failed logins by username
    failed_by_user = defaultdict(int)
    failed_by_ip = defaultdict(int)
    invalid_users = set()
    failed_entries = []
    
    for entry in entries:
        if entry["status"] == "Failed":
            failed_by_user[entry["username"]] += 1
            failed_by_ip[entry["ip_address"]] += 1
            failed_entries.append(entry)
            
            if entry["is_invalid_user"]:
                invalid_users.add(entry["username"])
    
    # Find users exceeding threshold
    suspicious_users = {
        user: count 
        for user, count in failed_by_user.items() 
        if count >= threshold
    }
    
    # Find IPs with multiple failures
    suspicious_ips = {
        ip: count 
        for ip, count in failed_by_ip.items() 
        if count >= threshold
    }
    
    logger.info(f"Found {len(failed_entries)} failed login attempts")
    logger.info(f"Found {len(suspicious_users)} users exceeding threshold")
    logger.info(f"Found {len(suspicious_ips)} IPs exceeding threshold")
    
    return {
        "total_failed": len(failed_entries),
        "failed_by_user": dict(failed_by_user),
        "failed_by_ip": dict(failed_by_ip),
        "suspicious_users": suspicious_users,
        "suspicious_ips": suspicious_ips,
        "invalid_users": list(invalid_users),
        "failed_entries": failed_entries
    }


def print_analysis_report(analysis, entries, threshold):
    """
    Print formatted analysis report.
    
    Args:
        analysis: Analysis results dictionary
        entries: All log entries
    """
    total_entries = len(entries)
    total_failed = analysis["total_failed"]
    total_successful = total_entries - total_failed
    
    print("\n" + "=" * 80)
    print("AUTHENTICATION LOG ANALYSIS REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Failed Login Threshold: {threshold}")
    print("=" * 80)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print(f"   Total authentication events: {total_entries}")
    print(f"   Successful logins: {total_successful}")
    print(f"   Failed logins: {total_failed}")
    
    if total_failed > 0:
        failure_rate = (total_failed / total_entries) * 100
        print(f"   Failure rate: {failure_rate:.1f}%")
    
    # Suspicious users
    if analysis["suspicious_users"]:
        print(f"\n⚠️  SUSPICIOUS USERS (≥{threshold} failed logins)")
        for user, count in sorted(analysis["suspicious_users"].items(), key=lambda x: x[1], reverse=True):
            print(f"   - {user}: {count} failed attempts")
    else:
        print(f"\n✓ No users exceeded {threshold} failed login threshold")
    
    # Suspicious IPs
    if analysis["suspicious_ips"]:
        print(f"\n⚠️  SUSPICIOUS IP ADDRESSES (≥{threshold} failed logins)")
        for ip, count in sorted(analysis["suspicious_ips"].items(), key=lambda x: x[1], reverse=True):
            print(f"   - {ip}: {count} failed attempts")
    else:
        print(f"\n✓ No IPs exceeded {threshold} failed login threshold")
    
    # Invalid users
    if analysis["invalid_users"]:
        print(f"\n🔍 INVALID USERNAMES ATTEMPTED ({len(analysis['invalid_users'])} unique)")
        for user in sorted(analysis["invalid_users"]):
            count = analysis["failed_by_user"][user]
            print(f"   - {user}: {count} attempts")
    
    # Top failed users
    if analysis["failed_by_user"]:
        print(f"\n📈 TOP FAILED LOGIN ATTEMPTS BY USER")
        top_users = sorted(analysis["failed_by_user"].items(), key=lambda x: x[1], reverse=True)[:5]
        for user, count in top_users:
            print(f"   {count:>3} attempts - {user}")
    
    # Top failed IPs
    if analysis["failed_by_ip"]:
        print(f"\n📈 TOP FAILED LOGIN ATTEMPTS BY IP")
        top_ips = sorted(analysis["failed_by_ip"].items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in top_ips:
            print(f"   {count:>3} attempts - {ip}")
    
    print("\n" + "=" * 80 + "\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Authentication Log Parser - Detect failed login attempts"
    )
    parser.add_argument(
        "--file",
        metavar="LOG_FILE",
        help="Path to authentication log file"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Generate and parse a sample log file"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=FAILED_LOGIN_THRESHOLD,
        help=f"Failed login threshold for alerts (default: {FAILED_LOGIN_THRESHOLD})"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Log Parser Started")
    logger.info("=" * 50)
    
    try:
        # Update threshold if specified
        threshold = args.threshold
        
        # Generate sample or use provided file
        if args.sample:
            logger.info("Generating sample log file...")
            log_file_path = generate_sample_log()
            print(f"✓ Generated sample log: {log_file_path}")
        elif args.file:
            log_file_path = args.file
        else:
            parser.print_help()
            print("\nExample usage:")
            print("  Generate sample:  python cybersecurity/log_parser.py --sample")
            print("  Parse log file:   python cybersecurity/log_parser.py --file /var/log/auth.log")
            return
        
        # Parse log file
        entries = parse_log_file(log_file_path, logger)
        
        if not entries:
            print("\n❌ No authentication events found in log file")
            logger.warning("No entries parsed from log file")
            return
        
        # Analyze failed logins
        analysis = analyze_failed_logins(entries, logger, threshold)
        
        # Print report
        print_analysis_report(analysis, entries, threshold)
        
        # Log summary
        if analysis["suspicious_users"]:
            logger.warning(f"{len(analysis['suspicious_users'])} suspicious users detected")
        if analysis["suspicious_ips"]:
            logger.warning(f"{len(analysis['suspicious_ips'])} suspicious IPs detected")
        
        logger.info("Log Parser Completed Successfully")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check log_parser.log for details.")


if __name__ == "__main__":
    main()
