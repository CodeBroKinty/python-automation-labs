"""
iam_analyzer.py
AWS IAM permission analyzer and security audit tool.

Usage:
    python cloud_automation/iam_analyzer.py --users
    python cloud_automation/iam_analyzer.py --security-audit
    python cloud_automation/iam_analyzer.py --export
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
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
LOG_FILE = "iam_analyzer.log"
REPORTS_DIR = Path("cloud_automation_reports")

# Dangerous permissions that indicate admin access
ADMIN_POLICIES = [
    'AdministratorAccess',
    'PowerUserAccess',
    'IAMFullAccess',
    'SecurityAudit'
]


def get_iam_client():
    """Create IAM client."""
    try:
        return boto3.client('iam')
    except NoCredentialsError:
        print("❌ AWS credentials not found!")
        sys.exit(1)


def list_users(iam_client, logger=None):
    """List all IAM users."""
    try:
        response = iam_client.list_users()
        users = response.get('Users', [])
        
        if logger:
            logger.info(f"Found {len(users)} IAM users")
        
        return users
    except ClientError as e:
        if logger:
            logger.error(f"Error listing users: {e}")
        print(f"❌ Error: {e}")
        return []


def get_user_access_keys(iam_client, username, logger=None):
    """Get access keys for a user."""
    try:
        response = iam_client.list_access_keys(UserName=username)
        return response.get('AccessKeyMetadata', [])
    except ClientError as e:
        if logger:
            logger.warning(f"Could not get access keys for {username}: {e}")
        return []


def get_user_policies(iam_client, username, logger=None):
    """Get attached policies for a user."""
    try:
        # Get attached managed policies
        response = iam_client.list_attached_user_policies(UserName=username)
        attached = response.get('AttachedPolicies', [])
        
        # Get inline policies
        inline_response = iam_client.list_user_policies(UserName=username)
        inline = inline_response.get('PolicyNames', [])
        
        return {
            'attached': [p['PolicyName'] for p in attached],
            'inline': inline
        }
    except ClientError as e:
        if logger:
            logger.warning(f"Could not get policies for {username}: {e}")
        return {'attached': [], 'inline': []}


def get_user_groups(iam_client, username, logger=None):
    """Get groups a user belongs to."""
    try:
        response = iam_client.list_groups_for_user(UserName=username)
        return [g['GroupName'] for g in response.get('Groups', [])]
    except ClientError as e:
        if logger:
            logger.warning(f"Could not get groups for {username}: {e}")
        return []


def check_mfa_enabled(iam_client, username, logger=None):
    """Check if user has MFA enabled."""
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        devices = response.get('MFADevices', [])
        return len(devices) > 0
    except ClientError as e:
        if logger:
            logger.warning(f"Could not check MFA for {username}: {e}")
        return None


def analyze_user(iam_client, username, logger=None):
    """Perform complete security analysis on a user."""
    if logger:
        logger.info(f"Analyzing user: {username}")
    
    analysis = {
        'username': username,
        'creation_date': None,
        'password_last_used': None,
        'access_keys': [],
        'policies': {'attached': [], 'inline': []},
        'groups': [],
        'mfa_enabled': None,
        'has_admin_access': False,
        'unused_credentials': False,
        'risk_level': 'UNKNOWN',
        'issues': []
    }
    
    # Get user details
    try:
        user_response = iam_client.get_user(UserName=username)
        user = user_response['User']
        analysis['creation_date'] = user['CreateDate']
        analysis['password_last_used'] = user.get('PasswordLastUsed')
    except ClientError:
        pass
    
    # Get access keys
    access_keys = get_user_access_keys(iam_client, username, logger)
    analysis['access_keys'] = [{
        'id': key['AccessKeyId'],
        'status': key['Status'],
        'created': key['CreateDate']
    } for key in access_keys]
    
    # Check for old/unused access keys
    now = datetime.now(timezone.utc)
    for key in analysis['access_keys']:
        age_days = (now - key['created']).days
        if age_days > 90:
            analysis['issues'].append(f"Access key {key['id'][-4:]} is {age_days} days old")
    
    # Get policies
    analysis['policies'] = get_user_policies(iam_client, username, logger)
    
    # Check for admin access
    for policy in analysis['policies']['attached']:
        if any(admin in policy for admin in ADMIN_POLICIES):
            analysis['has_admin_access'] = True
            analysis['issues'].append(f"Has admin policy: {policy}")
    
    # Get groups
    analysis['groups'] = get_user_groups(iam_client, username, logger)
    
    # Check MFA
    analysis['mfa_enabled'] = check_mfa_enabled(iam_client, username, logger)
    
    if not analysis['mfa_enabled']:
        analysis['issues'].append("MFA not enabled")
    
    # Check for unused credentials
    if analysis['password_last_used']:
        days_since_login = (now - analysis['password_last_used']).days
        if days_since_login > 90:
            analysis['unused_credentials'] = True
            analysis['issues'].append(f"No login in {days_since_login} days")
    
    # Calculate risk level
    if analysis['has_admin_access'] and not analysis['mfa_enabled']:
        analysis['risk_level'] = 'CRITICAL'
    elif analysis['has_admin_access']:
        analysis['risk_level'] = 'HIGH'
    elif not analysis['mfa_enabled'] or analysis['unused_credentials']:
        analysis['risk_level'] = 'MEDIUM'
    elif len(analysis['issues']) > 0:
        analysis['risk_level'] = 'LOW'
    else:
        analysis['risk_level'] = 'SECURE'
    
    return analysis


def print_user_list(analyses):
    """Print simple user list."""
    print("\n" + "=" * 100)
    print("IAM USER INVENTORY")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not analyses:
        print("\n✓ No IAM users found")
        print("\nℹ️  This is normal if you haven't created additional IAM users.")
        print("=" * 100 + "\n")
        return
    
    print(f"\n📊 SUMMARY")
    print(f"   Total users: {len(analyses)}")
    
    admin_users = sum(1 for a in analyses if a['has_admin_access'])
    no_mfa = sum(1 for a in analyses if not a['mfa_enabled'])
    
    print(f"   Users with admin access: {admin_users}")
    print(f"   Users without MFA: {no_mfa}")
    
    print(f"\n📋 USERS")
    print(f"   {'Username':<25} {'Access Keys':<12} {'MFA':<8} {'Admin':<8} {'Groups':<10}")
    print(f"   {'-'*25} {'-'*12} {'-'*8} {'-'*8} {'-'*10}")
    
    for analysis in analyses:
        mfa_status = "✓" if analysis['mfa_enabled'] else "✗"
        admin_status = "✓" if analysis['has_admin_access'] else "✗"
        key_count = len(analysis['access_keys'])
        group_count = len(analysis['groups'])
        
        print(
            f"   {analysis['username']:<25} "
            f"{key_count:<12} "
            f"{mfa_status:<8} "
            f"{admin_status:<8} "
            f"{group_count:<10}"
        )
    
    print("\n" + "=" * 100 + "\n")


def print_security_audit(analyses):
    """Print security audit results."""
    print("\n" + "=" * 100)
    print("IAM SECURITY AUDIT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not analyses:
        print("\n✓ No users to audit")
        print("=" * 100 + "\n")
        return
    
    # Count by risk level
    critical = [a for a in analyses if a['risk_level'] == 'CRITICAL']
    high = [a for a in analyses if a['risk_level'] == 'HIGH']
    medium = [a for a in analyses if a['risk_level'] == 'MEDIUM']
    low = [a for a in analyses if a['risk_level'] == 'LOW']
    secure = [a for a in analyses if a['risk_level'] == 'SECURE']
    
    print(f"\n📊 RISK SUMMARY")
    if critical:
        print(f"   🔴 CRITICAL: {len(critical)}")
    if high:
        print(f"   🟠 HIGH: {len(high)}")
    if medium:
        print(f"   🟡 MEDIUM: {len(medium)}")
    if low:
        print(f"   🟢 LOW: {len(low)}")
    if secure:
        print(f"   ✅ SECURE: {len(secure)}")
    
    # Show critical issues
    if critical:
        print(f"\n🔴 CRITICAL RISK USERS ({len(critical)})")
        for analysis in critical:
            print(f"   {analysis['username']}")
            for issue in analysis['issues']:
                print(f"      ⚠️  {issue}")
    
    # Show high risk
    if high:
        print(f"\n🟠 HIGH RISK USERS ({len(high)})")
        for analysis in high:
            print(f"   {analysis['username']}")
            for issue in analysis['issues']:
                print(f"      ⚠️  {issue}")
    
    # Show medium risk
    if medium:
        print(f"\n🟡 MEDIUM RISK USERS ({len(medium)})")
        for analysis in medium:
            print(f"   {analysis['username']}")
            for issue in analysis['issues']:
                print(f"      ⚠️  {issue}")
    
    # Summary recommendations
    print(f"\n💡 RECOMMENDATIONS")
    if critical or high:
        print(f"   1. Enable MFA for all admin users immediately")
    if no_mfa := sum(1 for a in analyses if not a['mfa_enabled']):
        print(f"   2. Enable MFA for {no_mfa} user(s) without it")
    if sum(1 for a in analyses if a['unused_credentials']):
        print(f"   3. Deactivate or remove unused credentials")
    if sum(1 for a in analyses if any('old' in i.lower() for i in a['issues'])):
        print(f"   4. Rotate old access keys (90+ days)")
    
    print("\n" + "=" * 100 + "\n")


def export_audit_csv(analyses, output_file):
    """Export audit to CSV."""
    REPORTS_DIR.mkdir(exist_ok=True)
    csv_path = REPORTS_DIR / output_file
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'username', 'risk_level', 'has_admin_access', 'mfa_enabled',
            'access_key_count', 'groups', 'issues', 'creation_date'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for analysis in analyses:
            row = {
                'username': analysis['username'],
                'risk_level': analysis['risk_level'],
                'has_admin_access': 'YES' if analysis['has_admin_access'] else 'NO',
                'mfa_enabled': 'YES' if analysis['mfa_enabled'] else 'NO',
                'access_key_count': len(analysis['access_keys']),
                'groups': ', '.join(analysis['groups']),
                'issues': '; '.join(analysis['issues']),
                'creation_date': analysis['creation_date'].strftime('%Y-%m-%d') if analysis['creation_date'] else ''
            }
            writer.writerow(row)
    
    print(f"📁 Exported to: {csv_path}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="IAM Analyzer - User permission and security audit"
    )
    parser.add_argument(
        "--users",
        action="store_true",
        help="List all IAM users"
    )
    parser.add_argument(
        "--security-audit",
        action="store_true",
        help="Perform security audit"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export audit to CSV"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("IAM Analyzer Started")
    logger.info("=" * 50)
    
    try:
        print("\n🔍 Connecting to AWS IAM...")
        
        # Create IAM client
        iam = get_iam_client()
        
        # List users
        users = list_users(iam, logger)
        
        if not users:
            print("\n✓ No IAM users found")
            print("\nℹ️  This is normal if you haven't created additional IAM users.")
            return
        
        print(f"👤 Found {len(users)} user(s). Analyzing...\n")
        
        # Analyze each user
        analyses = []
        for i, user in enumerate(users, 1):
            username = user['UserName']
            print(f"Analyzing [{i}/{len(users)}]: {username}...", end="\r")
            
            analysis = analyze_user(iam, username, logger)
            analyses.append(analysis)
        
        print()  # New line after progress
        
        # If no flags, show users list by default
        if not any([args.users, args.security_audit, args.export]):
            args.users = True
        
        # Display results
        if args.users:
            print_user_list(analyses)
        
        if args.security_audit:
            print_security_audit(analyses)
        
        if args.export:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_audit_csv(analyses, f"iam_audit_{timestamp}.csv")
        
        logger.info(f"IAM Analyzer Completed - {len(users)} users analyzed")
        
    except KeyboardInterrupt:
        logger.warning("Analysis cancelled")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Error: {e}")
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
