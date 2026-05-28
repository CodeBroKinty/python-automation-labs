"""
brute_force_detector.py
Advanced brute-force attack detection with time-based pattern analysis.

Usage:
    python cybersecurity/brute_force_detector.py --sample
    python cybersecurity/brute_force_detector.py --file <log_file> --window 60
"""

import sys
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "brute_force_detector.log"
TIME_WINDOW_SECONDS = 60  # Alert if X attempts within this window
VELOCITY_THRESHOLD = 5    # Alert if X attempts within time window
DISTRIBUTED_THRESHOLD = 3  # Alert if X different IPs target same user
ENUMERATION_THRESHOLD = 10 # Alert if X different users from same IP


def generate_sample_log():
    """Generate a sample log with various attack patterns."""
    sample_log = """
Jan 20 14:30:10 server sshd[5001]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:12 server sshd[5002]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:14 server sshd[5003]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:16 server sshd[5004]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:18 server sshd[5005]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:20 server sshd[5006]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:22 server sshd[5007]: Failed password for admin from 203.0.113.10 port 22 ssh2
Jan 20 14:30:24 server sshd[5008]: Failed password for root from 203.0.113.10 port 22 ssh2
Jan 20 14:30:26 server sshd[5009]: Failed password for root from 203.0.113.10 port 22 ssh2
Jan 20 14:30:28 server sshd[5010]: Failed password for root from 203.0.113.10 port 22 ssh2
Jan 20 14:32:00 server sshd[5011]: Failed password for admin from 198.51.100.5 port 22 ssh2
Jan 20 14:32:05 server sshd[5012]: Failed password for admin from 198.51.100.6 port 22 ssh2
Jan 20 14:32:10 server sshd[5013]: Failed password for admin from 198.51.100.7 port 22 ssh2
Jan 20 14:32:15 server sshd[5014]: Failed password for admin from 198.51.100.8 port 22 ssh2
Jan 20 14:35:00 server sshd[5015]: Failed password for user1 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:02 server sshd[5016]: Failed password for user2 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:04 server sshd[5017]: Failed password for user3 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:06 server sshd[5018]: Failed password for user4 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:08 server sshd[5019]: Failed password for user5 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:10 server sshd[5020]: Failed password for user6 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:12 server sshd[5021]: Failed password for user7 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:14 server sshd[5022]: Failed password for user8 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:16 server sshd[5023]: Failed password for user9 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:18 server sshd[5024]: Failed password for user10 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:20 server sshd[5025]: Failed password for user11 from 192.0.2.50 port 22 ssh2
Jan 20 14:35:22 server sshd[5026]: Failed password for user12 from 192.0.2.50 port 22 ssh2
Jan 20 14:40:00 server sshd[5027]: Accepted password for admin from 192.168.1.100 port 22 ssh2
Jan 20 14:45:00 server sshd[5028]: Failed password for backup from 10.0.0.20 port 22 ssh2
Jan 20 14:45:15 server sshd[5029]: Failed password for backup from 10.0.0.20 port 22 ssh2
Jan 20 14:45:30 server sshd[5030]: Accepted password for backup from 10.0.0.20 port 22 ssh2
""".strip()
    
    sample_file = Path("sample_brute_force.log")
    sample_file.write_text(sample_log)
    return sample_file


def parse_auth_log_line(line): # Parse a single line from the authentication log
    """Parse authentication log line."""
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted) password for (invalid user )?(\S+) from (\S+)'
    
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        status = match.group(2)
        invalid_prefix = match.group(3)
        username = match.group(4)
        ip_address = match.group(5)
        
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


def parse_log_file(log_file_path, logger): # Parse the authentication log file
    """Parse authentication log file."""
    log_file = Path(log_file_path)
    
    if not log_file.exists():
        logger.error(f"Log file not found: {log_file_path}")
        return []
    
    parsed_entries = []
    
    logger.info(f"Parsing log file: {log_file_path}")
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = parse_auth_log_line(line)
                if entry:
                    parsed_entries.append(entry)
        
        logger.info(f"Parsed {len(parsed_entries)} authentication events")
        
    except Exception as e:
        logger.exception(f"Error reading log file: {e}")
        return []
    
    # Sort by timestamp
    parsed_entries.sort(key=lambda x: x["timestamp"] if x["timestamp"] else datetime.min)
    
    return parsed_entries


def detect_velocity_attacks(entries, time_window, velocity_threshold, logger): # Detect rapid-fire login attempts (velocity attacks)
    """
    Detect rapid-fire login attempts (velocity attacks).
    
    Args:
        entries: Parsed log entries
        time_window: Time window in seconds
        velocity_threshold: Number of attempts to trigger alert
        logger: Logger instance
    
    Returns:
        list: Detected velocity attacks
    """
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    velocity_attacks = []
    
    # Group by IP address
    by_ip = defaultdict(list)
    for entry in failed_entries:
        by_ip[entry["ip_address"]].append(entry)
    
    # Check each IP for velocity attacks
    for ip, ip_entries in by_ip.items():
        for i, entry in enumerate(ip_entries):
            # Count attempts within time window
            window_start = entry["timestamp"]
            window_end = window_start + timedelta(seconds=time_window)
            
            attempts_in_window = [
                e for e in ip_entries[i:]
                if e["timestamp"] >= window_start and e["timestamp"] <= window_end
            ]
            
            if len(attempts_in_window) >= velocity_threshold:
                velocity_attacks.append({
                    "ip": ip,
                    "start_time": window_start,
                    "attempts": len(attempts_in_window),
                    "time_window": time_window,
                    "usernames": list(set(e["username"] for e in attempts_in_window))
                })
                logger.warning(f"Velocity attack: {ip} - {len(attempts_in_window)} attempts in {time_window}s")
                break  # Only report once per IP
    
    return velocity_attacks


def detect_distributed_attacks(entries, distributed_threshold, logger): # Detect coordinated attacks from multiple IPs targeting same user
    """
    Detect coordinated attacks from multiple IPs targeting same user.
    
    Args:
        entries: Parsed log entries
        distributed_threshold: Number of unique IPs to trigger alert
        logger: Logger instance
    
    Returns:
        list: Detected distributed attacks
    """
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    distributed_attacks = []
    
    # Group by username
    by_user = defaultdict(list)
    for entry in failed_entries:
        by_user[entry["username"]].append(entry)
    
    # Check each user for distributed attacks
    for username, user_entries in by_user.items():
        unique_ips = set(e["ip_address"] for e in user_entries)
        
        if len(unique_ips) >= distributed_threshold:
            distributed_attacks.append({
                "username": username,
                "unique_ips": list(unique_ips),
                "ip_count": len(unique_ips),
                "total_attempts": len(user_entries)
            })
            logger.warning(f"Distributed attack: {username} targeted by {len(unique_ips)} IPs")
    
    return distributed_attacks


def detect_account_enumeration(entries, enumeration_threshold, logger): # Detect account enumeration (testing many usernames from one IP)
    """
    Detect account enumeration (testing many usernames from one IP).
    
    Args:
        entries: Parsed log entries
        enumeration_threshold: Number of unique users to trigger alert
        logger: Logger instance
    
    Returns:
        list: Detected enumeration attempts
    """
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    enumeration_attacks = []
    
    # Group by IP
    by_ip = defaultdict(list)
    for entry in failed_entries:
        by_ip[entry["ip_address"]].append(entry)
    
    # Check each IP for enumeration
    for ip, ip_entries in by_ip.items():
        unique_users = set(e["username"] for e in ip_entries)
        
        if len(unique_users) >= enumeration_threshold:
            enumeration_attacks.append({
                "ip": ip,
                "unique_users": list(unique_users),
                "user_count": len(unique_users),
                "total_attempts": len(ip_entries)
            })
            logger.warning(f"Account enumeration: {ip} tested {len(unique_users)} usernames")
    
    return enumeration_attacks


def print_detection_report(velocity, distributed, enumeration, time_window, velocity_threshold, distributed_threshold, enumeration_threshold): # Print formatted attack detection report
    """Print formatted attack detection report."""
    print("\n" + "=" * 80)
    print("BRUTE-FORCE ATTACK DETECTION REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    print(f"\n🔍 DETECTION CRITERIA")
    print(f"   Velocity attack: {velocity_threshold}+ attempts within {time_window} seconds")
    print(f"   Distributed attack: {distributed_threshold}+ IPs targeting same user")
    print(f"   Account enumeration: {enumeration_threshold}+ usernames from same IP")
    
    total_threats = len(velocity) + len(distributed) + len(enumeration)
    
    if total_threats == 0:
        print(f"\n✓ NO ATTACKS DETECTED")
    else:
        print(f"\n⚠️  {total_threats} ATTACK PATTERN(S) DETECTED")
    
    # Velocity attacks
    if velocity:
        print(f"\n🚨 VELOCITY ATTACKS ({len(velocity)} detected)")
        print("   Rapid-fire login attempts from single source")
        for attack in velocity:
            print(f"\n   IP: {attack['ip']}")
            print(f"      Attempts: {attack['attempts']} in {attack['time_window']}s")
            print(f"      Start: {attack['start_time'].strftime('%H:%M:%S')}")
            print(f"      Targeted users: {', '.join(attack['usernames'][:5])}")
    
    # Distributed attacks
    if distributed:
        print(f"\n🚨 DISTRIBUTED ATTACKS ({len(distributed)} detected)")
        print("   Coordinated attacks from multiple IPs")
        for attack in distributed:
            print(f"\n   Target: {attack['username']}")
            print(f"      Attack IPs: {attack['ip_count']}")
            print(f"      Total attempts: {attack['total_attempts']}")
            print(f"      Sources: {', '.join(attack['unique_ips'][:5])}")
    
    # Account enumeration
    if enumeration:
        print(f"\n🚨 ACCOUNT ENUMERATION ({len(enumeration)} detected)")
        print("   Testing multiple usernames to find valid accounts")
        for attack in enumeration:
            print(f"\n   Source IP: {attack['ip']}")
            print(f"      Usernames tested: {attack['user_count']}")
            print(f"      Total attempts: {attack['total_attempts']}")
            print(f"      Sample users: {', '.join(attack['unique_users'][:10])}")
    
    print("\n" + "=" * 80)
    
    # Recommendations
    if total_threats > 0:
        print("\n💡 RECOMMENDED ACTIONS:")
        if velocity:
            print("   • Implement rate limiting on authentication endpoints")
            print("   • Block IPs with velocity attacks in firewall")
        if distributed:
            print("   • Enable account lockout after failed attempts")
            print("   • Investigate if user accounts are compromised")
        if enumeration:
            print("   • Hide user enumeration errors (return generic message)")
            print("   • Monitor for follow-up targeted attacks")
        print()
    
    print("=" * 80 + "\n")


def main(): # Main execution function
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Advanced Brute-Force Attack Detector"
    )
    parser.add_argument(
        "--file",
        metavar="LOG_FILE",
        help="Path to authentication log file"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Generate and analyze sample log with attack patterns"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=TIME_WINDOW_SECONDS,
        help=f"Time window in seconds (default: {TIME_WINDOW_SECONDS})"
    )
    parser.add_argument(
        "--velocity",
        type=int,
        default=VELOCITY_THRESHOLD,
        help=f"Velocity threshold (default: {VELOCITY_THRESHOLD})"
    )
    parser.add_argument(
        "--distributed",
        type=int,
        default=DISTRIBUTED_THRESHOLD,
        help=f"Distributed attack threshold (default: {DISTRIBUTED_THRESHOLD})"
    )
    parser.add_argument(
        "--enumeration",
        type=int,
        default=ENUMERATION_THRESHOLD,
        help=f"Enumeration threshold (default: {ENUMERATION_THRESHOLD})"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Brute-Force Detector Started")
    logger.info("=" * 50)
    
    try:
        # Generate sample or use provided file
        if args.sample:
            logger.info("Generating sample log with attack patterns...")
            log_file_path = generate_sample_log()
            print(f"✓ Generated sample log: {log_file_path}\n")
        elif args.file:
            log_file_path = args.file
        else:
            parser.print_help()
            print("\nExample usage:")
            print("  Analyze sample:  python cybersecurity/brute_force_detector.py --sample")
            print("  Analyze log:     python cybersecurity/brute_force_detector.py --file /var/log/auth.log")
            return
        
        # Parse log file
        entries = parse_log_file(log_file_path, logger)
        
        if not entries:
            print("\n❌ No authentication events found")
            return
        
        print(f"📊 Analyzing {len(entries)} authentication events...\n")
        
        # Detect attack patterns
        velocity_attacks = detect_velocity_attacks(entries, args.window, args.velocity, logger)
        distributed_attacks = detect_distributed_attacks(entries, args.distributed, logger)
        enumeration_attacks = detect_account_enumeration(entries, args.enumeration, logger)
        
        # Print report
        print_detection_report(
            velocity_attacks,
            distributed_attacks,
            enumeration_attacks,
            args.window,
            args.velocity,
            args.distributed,
            args.enumeration
        )
        
        logger.info("Brute-Force Detector Completed Successfully")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check brute_force_detector.log for details.")


if __name__ == "__main__":
    main()
