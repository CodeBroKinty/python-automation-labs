"""
ping_sweep.py
Network host discovery using ICMP ping sweep.

Usage:
    python networking/ping_sweep.py --target 192.168.1.0/24
    python networking/ping_sweep.py --target 192.168.1.1-192.168.1.50
    python networking/ping_sweep.py --target 192.168.1.1
"""

import subprocess
import sys
import platform
import ipaddress
import concurrent.futures
from pathlib import Path
from datetime import datetime
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "ping_sweep.log"
MAX_WORKERS = 50  # Concurrent ping threads
PING_TIMEOUT = 1  # Seconds to wait for ping response


def ping_host(ip_address, timeout=PING_TIMEOUT):
    """
    Ping a single host to check if it's alive.
    
    Args:
        ip_address: IP address to ping
        timeout: Timeout in seconds
    
    Returns:
        dict: Result with IP, status, and response time
    """
    # Determine ping command based on OS
    system = platform.system().lower()
    
    if system == "windows":
        # Windows: ping -n 1 -w timeout_ms IP
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip_address)]
    else:
        # Linux/Mac: ping -c 1 -W timeout IP
        command = ["ping", "-c", "1", "-W", str(timeout), str(ip_address)]
    
    try:
        # Run ping command
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1,
            text=True
        )
        
        # Check if ping was successful
        if result.returncode == 0:
            # Extract response time (basic parsing)
            output = result.stdout
            
            # Try to extract response time
            if system == "windows":
                # Windows: time=XXms or time<1ms
                if "time=" in output or "time<" in output:
                    response_time = "< 1ms" if "time<" in output else output.split("time=")[1].split("ms")[0] + "ms"
                else:
                    response_time = "unknown"
            else:
                # Linux: time=XX.X ms
                if "time=" in output:
                    response_time = output.split("time=")[1].split("ms")[0].strip() + "ms"
                else:
                    response_time = "unknown"
            
            return {
                "ip": str(ip_address),
                "status": "up",
                "response_time": response_time
            }
        else:
            return {
                "ip": str(ip_address),
                "status": "down",
                "response_time": None
            }
            
    except subprocess.TimeoutExpired:
        return {
            "ip": str(ip_address),
            "status": "timeout",
            "response_time": None
        }
    except Exception as e:
        return {
            "ip": str(ip_address),
            "status": "error",
            "response_time": None,
            "error": str(e)
        }


def parse_target(target):
    """
    Parse target specification into list of IP addresses.
    
    Supports:
    - Single IP: 192.168.1.1
    - CIDR range: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.50
    
    Args:
        target: Target specification string
    
    Returns:
        list: List of IP addresses to scan
    """
    ip_list = []
    
    try:
        # Check if CIDR notation (e.g., 192.168.1.0/24)
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        
        # Check if range notation (e.g., 192.168.1.1-192.168.1.50)
        elif "-" in target:
            start_ip, end_ip = target.split("-")
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            # Generate IPs in range
            current = start
            while current <= end:
                ip_list.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
        
        # Single IP
        else:
            # Validate it's a valid IP
            ipaddress.ip_address(target)
            ip_list = [target]
    
    except ValueError as e:
        raise ValueError(f"Invalid target specification: {target}. Error: {e}")
    
    return ip_list


def ping_sweep(targets, max_workers=MAX_WORKERS, logger=None):
    """
    Perform ping sweep on multiple targets concurrently.
    
    Args:
        targets: List of IP addresses to ping
        max_workers: Maximum concurrent threads
        logger: Logger instance
    
    Returns:
        dict: Results with live and dead hosts
    """
    results = {
        "live_hosts": [],
        "dead_hosts": [],
        "errors": []
    }
    
    total = len(targets)
    completed = 0
    
    if logger:
        logger.info(f"Starting ping sweep of {total} hosts with {max_workers} workers")
    
    print(f"\n🔍 Scanning {total} host(s)...")
    print(f"⚙️  Using {max_workers} concurrent threads\n")
    
    # Use ThreadPoolExecutor for concurrent pinging
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all ping tasks
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in targets}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            result = future.result()
            
            # Progress indicator
            if completed % 10 == 0 or completed == total:
                print(f"Progress: {completed}/{total} ({(completed/total)*100:.1f}%)", end="\r")
            
            # Categorize result
            if result["status"] == "up":
                results["live_hosts"].append(result)
                if logger:
                    logger.info(f"UP: {result['ip']} ({result['response_time']})")
            elif result["status"] in ["down", "timeout"]:
                results["dead_hosts"].append(result)
                if logger:
                    logger.debug(f"DOWN: {result['ip']}")
            else:
                results["errors"].append(result)
                if logger:
                    logger.warning(f"ERROR: {result['ip']} - {result.get('error', 'unknown')}")
    
    print()  # New line after progress
    
    if logger:
        logger.info(f"Sweep complete: {len(results['live_hosts'])} live, {len(results['dead_hosts'])} dead")
    
    return results


def print_results(results):
    """Print formatted ping sweep results."""
    live = results["live_hosts"]
    dead = results["dead_hosts"]
    errors = results["errors"]
    
    total = len(live) + len(dead) + len(errors)
    
    print("\n" + "=" * 70)
    print("PING SWEEP RESULTS")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print(f"   Total hosts scanned: {total}")
    print(f"   Live hosts: {len(live)} ({(len(live)/total)*100:.1f}%)")
    print(f"   Dead/Timeout: {len(dead)}")
    print(f"   Errors: {len(errors)}")
    
    # Live hosts
    if live:
        print(f"\n✅ LIVE HOSTS ({len(live)})")
        
        # Sort by IP
        live_sorted = sorted(live, key=lambda x: ipaddress.ip_address(x["ip"]))
        
        for host in live_sorted:
            response = host['response_time'] if host['response_time'] else 'N/A'
            print(f"   {host['ip']:<15} - Response time: {response}")
    
    # Errors (if any)
    if errors:
        print(f"\n⚠️  ERRORS ({len(errors)})")
        for host in errors:
            error_msg = host.get('error', 'Unknown error')
            print(f"   {host['ip']:<15} - {error_msg}")
    
    print("\n" + "=" * 70 + "\n")


def export_results(results, output_file):
    """Export results to text file."""
    with open(output_file, 'w') as f:
        f.write("PING SWEEP RESULTS\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("LIVE HOSTS:\n")
        live_sorted = sorted(results["live_hosts"], key=lambda x: ipaddress.ip_address(x["ip"]))
        for host in live_sorted:
            f.write(f"{host['ip']}\n")
        
        f.write(f"\nTotal: {len(results['live_hosts'])} live hosts\n")
    
    print(f"📁 Results exported to: {output_file}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Ping Sweep - Network host discovery tool"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target: single IP, CIDR (192.168.1.0/24), or range (192.168.1.1-192.168.1.50)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Number of concurrent threads (default: {MAX_WORKERS})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=PING_TIMEOUT,
        help=f"Ping timeout in seconds (default: {PING_TIMEOUT})"
    )
    parser.add_argument(
        "--output",
        help="Export live hosts to file"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Ping Sweep Started")
    logger.info("=" * 50)
    
    try:
        # Parse target
        print(f"🎯 Target: {args.target}")
        targets = parse_target(args.target)
        
        if not targets:
            print("\n❌ No valid targets to scan")
            return
        
        # Perform ping sweep
        start_time = datetime.now()
        
        results = ping_sweep(targets, args.workers, logger)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print results
        print_results(results)
        
        print(f"⏱️  Scan completed in {duration:.2f} seconds")
        
        # Export if requested
        if args.output:
            export_results(results, args.output)
        
        logger.info(f"Ping Sweep Completed in {duration:.2f}s")
        
    except KeyboardInterrupt:
        logger.warning("Scan cancelled by user")
        print("\n\nScan cancelled.")
    except ValueError as e:
        logger.error(f"Invalid target: {e}")
        print(f"\n❌ Error: {e}")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check ping_sweep.log for details.")


if __name__ == "__main__":
    main()
