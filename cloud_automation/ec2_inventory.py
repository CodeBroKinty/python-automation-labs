"""
ec2_inventory.py
AWS EC2 instance inventory and security analysis tool.

Usage:
    python cloud_automation/ec2_inventory.py --list
    python cloud_automation/ec2_inventory.py --details
    python cloud_automation/ec2_inventory.py --security-check
    python cloud_automation/ec2_inventory.py --export
"""

import sys
from pathlib import Path
from datetime import datetime
import csv
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Import boto3
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("❌ boto3 not installed. Run: pip install boto3")
    sys.exit(1)

# Configuration
LOG_FILE = "ec2_inventory.log"
REPORTS_DIR = Path("cloud_automation_reports")


def get_ec2_client(region='us-east-1'):
    """Create EC2 client."""
    try:
        return boto3.client('ec2', region_name=region)
    except NoCredentialsError:
        print("❌ AWS credentials not found!")
        print("Run: aws configure")
        print("Or create ~/.aws/credentials file")
        sys.exit(1)


def get_all_instances(ec2_client, logger=None):
    """
    Get all EC2 instances.
    
    Args:
        ec2_client: boto3 EC2 client
        logger: Logger instance
    
    Returns:
        list: EC2 instance data
    """
    instances = []
    
    try:
        response = ec2_client.describe_instances()
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append(instance)
        
        if logger:
            logger.info(f"Found {len(instances)} EC2 instances")
        
        return instances
        
    except ClientError as e:
        if logger:
            logger.error(f"AWS API error: {e}")
        print(f"❌ Error: {e}")
        return []


def extract_instance_info(instance):
    """Extract relevant info from instance object."""
    # Get instance name from tags
    name = "N/A"
    if 'Tags' in instance:
        for tag in instance['Tags']:
            if tag['Key'] == 'Name':
                name = tag['Value']
                break
    
    # Get public IP
    public_ip = instance.get('PublicIpAddress', 'N/A')
    private_ip = instance.get('PrivateIpAddress', 'N/A')
    
    # Get security groups
    security_groups = [sg['GroupName'] for sg in instance.get('SecurityGroups', [])]
    
    return {
        'instance_id': instance['InstanceId'],
        'name': name,
        'instance_type': instance['InstanceType'],
        'state': instance['State']['Name'],
        'public_ip': public_ip,
        'private_ip': private_ip,
        'launch_time': instance['LaunchTime'],
        'security_groups': security_groups,
        'key_name': instance.get('KeyName', 'N/A'),
        'vpc_id': instance.get('VpcId', 'N/A'),
        'subnet_id': instance.get('SubnetId', 'N/A'),
        'platform': instance.get('Platform', 'Linux/Unix')
    }


def check_security_issues(instance_info, logger=None):
    """Check for common security issues."""
    issues = []
    
    # Check if instance has public IP
    if instance_info['public_ip'] != 'N/A':
        issues.append("Has public IP address")
    
    # Check if using default security group
    if 'default' in [sg.lower() for sg in instance_info['security_groups']]:
        issues.append("Using default security group")
    
    # Check if key pair is missing
    if instance_info['key_name'] == 'N/A':
        issues.append("No SSH key pair configured")
    
    if logger and issues:
        logger.warning(f"{instance_info['instance_id']}: {', '.join(issues)}")
    
    return issues


def print_instance_list(instances):
    """Print simple instance list."""
    print("\n" + "=" * 100)
    print("EC2 INSTANCE INVENTORY")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not instances:
        print("\n✓ No EC2 instances found (or none in this region)")
        print("\nℹ️  This is normal if you haven't launched any instances yet.")
        print("=" * 100 + "\n")
        return
    
    print(f"\n📊 SUMMARY")
    print(f"   Total instances: {len(instances)}")
    
    running = sum(1 for i in instances if i['state'] == 'running')
    stopped = sum(1 for i in instances if i['state'] == 'stopped')
    
    print(f"   Running: {running}")
    print(f"   Stopped: {stopped}")
    
    print(f"\n📋 INSTANCES")
    print(f"   {'ID':<20} {'Name':<25} {'Type':<15} {'State':<10} {'Public IP':<15}")
    print(f"   {'-'*20} {'-'*25} {'-'*15} {'-'*10} {'-'*15}")
    
    for instance in instances:
        print(
            f"   {instance['instance_id']:<20} "
            f"{instance['name']:<25} "
            f"{instance['instance_type']:<15} "
            f"{instance['state']:<10} "
            f"{instance['public_ip']:<15}"
        )
    
    print("\n" + "=" * 100 + "\n")


def print_instance_details(instances):
    """Print detailed instance information."""
    print("\n" + "=" * 100)
    print("EC2 INSTANCE DETAILS")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not instances:
        print("\n✓ No EC2 instances found")
        print("=" * 100 + "\n")
        return
    
    for instance in instances:
        print(f"\n📍 {instance['name']} ({instance['instance_id']})")
        print(f"   Type: {instance['instance_type']}")
        print(f"   State: {instance['state']}")
        print(f"   Platform: {instance['platform']}")
        print(f"   Public IP: {instance['public_ip']}")
        print(f"   Private IP: {instance['private_ip']}")
        print(f"   Key Pair: {instance['key_name']}")
        print(f"   VPC: {instance['vpc_id']}")
        print(f"   Subnet: {instance['subnet_id']}")
        print(f"   Security Groups: {', '.join(instance['security_groups'])}")
        print(f"   Launch Time: {instance['launch_time'].strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n" + "=" * 100 + "\n")


def print_security_check(instances, logger=None):
    """Print security analysis."""
    print("\n" + "=" * 100)
    print("EC2 SECURITY ANALYSIS")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not instances:
        print("\n✓ No instances to analyze")
        print("=" * 100 + "\n")
        return
    
    total_issues = 0
    
    for instance in instances:
        issues = check_security_issues(instance, logger)
        
        if issues:
            total_issues += len(issues)
            print(f"\n⚠️  {instance['name']} ({instance['instance_id']})")
            for issue in issues:
                print(f"   - {issue}")
    
    if total_issues == 0:
        print("\n✓ No security issues detected")
    else:
        print(f"\n📊 Total issues found: {total_issues}")
    
    print("\n" + "=" * 100 + "\n")


def export_to_csv(instances, output_file):
    """Export instance inventory to CSV."""
    REPORTS_DIR.mkdir(exist_ok=True)
    csv_path = REPORTS_DIR / output_file
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'instance_id', 'name', 'instance_type', 'state',
            'public_ip', 'private_ip', 'platform', 'key_name',
            'vpc_id', 'subnet_id', 'security_groups', 'launch_time'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for instance in instances:
            row = instance.copy()
            row['security_groups'] = ', '.join(row['security_groups'])
            row['launch_time'] = row['launch_time'].strftime('%Y-%m-%d %H:%M:%S')
            writer.writerow(row)
    
    print(f"📁 Exported to: {csv_path}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="EC2 Inventory - AWS instance analysis tool"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all EC2 instances"
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Show detailed instance information"
    )
    parser.add_argument(
        "--security-check",
        action="store_true",
        help="Perform security analysis"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export inventory to CSV"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("EC2 Inventory Started")
    logger.info("=" * 50)
    
    try:
        print(f"\n🔍 Connecting to AWS (region: {args.region})...")
        
        # Create EC2 client
        ec2 = get_ec2_client(args.region)
        
        # Get all instances
        raw_instances = get_all_instances(ec2, logger)
        instances = [extract_instance_info(i) for i in raw_instances]
        
        # If no flags, show list by default
        if not any([args.list, args.details, args.security_check, args.export]):
            args.list = True
        
        # Execute requested actions
        if args.list:
            print_instance_list(instances)
        
        if args.details:
            print_instance_details(instances)
        
        if args.security_check:
            print_security_check(instances, logger)
        
        if args.export:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_to_csv(instances, f"ec2_inventory_{timestamp}.csv")
        
        logger.info(f"EC2 Inventory Completed - {len(instances)} instances")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Error: {e}")
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
