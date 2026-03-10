"""
s3_security_audit.py
AWS S3 bucket security audit and compliance checker.

Usage:
    python cloud_automation/s3_security_audit.py --audit
    python cloud_automation/s3_security_audit.py --detailed
    python cloud_automation/s3_security_audit.py --export
"""

import sys
from pathlib import Path
from datetime import datetime
import csv
import json
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
LOG_FILE = "s3_audit.log"
REPORTS_DIR = Path("cloud_automation_reports")


def get_s3_client():
    """Create S3 client."""
    try:
        return boto3.client('s3')
    except NoCredentialsError:
        print("❌ AWS credentials not found!")
        print("Run: aws configure")
        sys.exit(1)


def list_buckets(s3_client, logger=None):
    """List all S3 buckets."""
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        if logger:
            logger.info(f"Found {len(buckets)} S3 buckets")
        
        return buckets
    except ClientError as e:
        if logger:
            logger.error(f"Error listing buckets: {e}")
        print(f"❌ Error: {e}")
        return []


def check_public_access(s3_client, bucket_name, logger=None):
    """Check if bucket has public access."""
    try:
        # Check bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return True, "Public via ACL"
        
        # Check public access block
        try:
            block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = block.get('PublicAccessBlockConfiguration', {})
            
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                return True, "Public access not fully blocked"
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                return True, "No public access block configured"
        
        return False, "Private"
        
    except ClientError as e:
        if logger:
            logger.warning(f"Could not check public access for {bucket_name}: {e}")
        return None, f"Error: {str(e)[:50]}"


def check_encryption(s3_client, bucket_name, logger=None):
    """Check if bucket has encryption enabled."""
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        
        if rules:
            encryption_type = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'Unknown')
            return True, encryption_type
        else:
            return False, "None"
            
    except ClientError as e:
        if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
            return False, "None"
        else:
            if logger:
                logger.warning(f"Could not check encryption for {bucket_name}: {e}")
            return None, "Error"


def check_versioning(s3_client, bucket_name, logger=None):
    """Check if bucket has versioning enabled."""
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get('Status', 'Disabled')
        return status == 'Enabled', status
    except ClientError as e:
        if logger:
            logger.warning(f"Could not check versioning for {bucket_name}: {e}")
        return None, "Error"


def check_logging(s3_client, bucket_name, logger=None):
    """Check if bucket has logging enabled."""
    try:
        logging = s3_client.get_bucket_logging(Bucket=bucket_name)
        logging_config = logging.get('LoggingEnabled')
        
        if logging_config:
            target = logging_config.get('TargetBucket', 'Unknown')
            return True, f"Enabled (→ {target})"
        else:
            return False, "Disabled"
            
    except ClientError as e:
        if logger:
            logger.warning(f"Could not check logging for {bucket_name}: {e}")
        return None, "Error"


def get_bucket_size(s3_client, bucket_name, logger=None):
    """Estimate bucket size (object count)."""
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        key_count = response.get('KeyCount', 0)
        
        if key_count > 0:
            return "Has objects"
        else:
            return "Empty"
    except ClientError as e:
        if logger:
            logger.warning(f"Could not check size for {bucket_name}: {e}")
        return "Unknown"


def audit_bucket(s3_client, bucket_name, logger=None):
    """Perform complete security audit on a bucket."""
    if logger:
        logger.info(f"Auditing bucket: {bucket_name}")
    
    audit_result = {
        'bucket_name': bucket_name,
        'creation_date': None,
        'is_public': None,
        'public_status': None,
        'encrypted': None,
        'encryption_type': None,
        'versioning': None,
        'versioning_status': None,
        'logging': None,
        'logging_status': None,
        'size_status': None,
        'risk_level': 'UNKNOWN',
        'issues': []
    }
    
    # Get bucket info
    try:
        buckets = list_buckets(s3_client)
        for bucket in buckets:
            if bucket['Name'] == bucket_name:
                audit_result['creation_date'] = bucket['CreationDate']
                break
    except:
        pass
    
    # Check public access
    is_public, public_status = check_public_access(s3_client, bucket_name, logger)
    audit_result['is_public'] = is_public
    audit_result['public_status'] = public_status
    
    if is_public:
        audit_result['issues'].append("PUBLIC ACCESS ENABLED")
    
    # Check encryption
    encrypted, encryption_type = check_encryption(s3_client, bucket_name, logger)
    audit_result['encrypted'] = encrypted
    audit_result['encryption_type'] = encryption_type
    
    if not encrypted:
        audit_result['issues'].append("No encryption")
    
    # Check versioning
    versioning, versioning_status = check_versioning(s3_client, bucket_name, logger)
    audit_result['versioning'] = versioning
    audit_result['versioning_status'] = versioning_status
    
    if not versioning:
        audit_result['issues'].append("Versioning disabled")
    
    # Check logging
    logging_enabled, logging_status = check_logging(s3_client, bucket_name, logger)
    audit_result['logging'] = logging_enabled
    audit_result['logging_status'] = logging_status
    
    if not logging_enabled:
        audit_result['issues'].append("Logging disabled")
    
    # Check size
    audit_result['size_status'] = get_bucket_size(s3_client, bucket_name, logger)
    
    # Calculate risk level
    if is_public:
        audit_result['risk_level'] = 'CRITICAL'
    elif not encrypted and audit_result['size_status'] != 'Empty':
        audit_result['risk_level'] = 'HIGH'
    elif not versioning or not logging_enabled:
        audit_result['risk_level'] = 'MEDIUM'
    elif len(audit_result['issues']) == 0:
        audit_result['risk_level'] = 'LOW'
    else:
        audit_result['risk_level'] = 'MEDIUM'
    
    return audit_result


def print_audit_summary(audit_results):
    """Print audit summary."""
    print("\n" + "=" * 100)
    print("S3 BUCKET SECURITY AUDIT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not audit_results:
        print("\n✓ No S3 buckets found")
        print("\nℹ️  This is normal if you haven't created any buckets yet.")
        print("=" * 100 + "\n")
        return
    
    # Count by risk level
    critical = sum(1 for r in audit_results if r['risk_level'] == 'CRITICAL')
    high = sum(1 for r in audit_results if r['risk_level'] == 'HIGH')
    medium = sum(1 for r in audit_results if r['risk_level'] == 'MEDIUM')
    low = sum(1 for r in audit_results if r['risk_level'] == 'LOW')
    
    print(f"\n📊 SUMMARY")
    print(f"   Total buckets: {len(audit_results)}")
    print(f"   Risk levels:")
    if critical > 0:
        print(f"      🔴 CRITICAL: {critical}")
    if high > 0:
        print(f"      🟠 HIGH: {high}")
    if medium > 0:
        print(f"      🟡 MEDIUM: {medium}")
    if low > 0:
        print(f"      🟢 LOW: {low}")
    
    # Show buckets by risk
    if critical > 0:
        print(f"\n🔴 CRITICAL RISK BUCKETS ({critical})")
        for result in [r for r in audit_results if r['risk_level'] == 'CRITICAL']:
            print(f"   {result['bucket_name']}")
            for issue in result['issues']:
                print(f"      ⚠️  {issue}")
    
    if high > 0:
        print(f"\n🟠 HIGH RISK BUCKETS ({high})")
        for result in [r for r in audit_results if r['risk_level'] == 'HIGH']:
            print(f"   {result['bucket_name']}")
            for issue in result['issues']:
                print(f"      ⚠️  {issue}")
    
    print("\n" + "=" * 100 + "\n")


def print_detailed_audit(audit_results):
    """Print detailed audit results."""
    print("\n" + "=" * 100)
    print("S3 BUCKET DETAILED AUDIT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not audit_results:
        print("\n✓ No S3 buckets found")
        print("=" * 100 + "\n")
        return
    
    for result in audit_results:
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }.get(result['risk_level'], '⚪')
        
        print(f"\n{risk_emoji} {result['bucket_name']} [{result['risk_level']}]")
        print(f"   Created: {result['creation_date'].strftime('%Y-%m-%d') if result['creation_date'] else 'Unknown'}")
        print(f"   Public Access: {result['public_status']}")
        print(f"   Encryption: {result['encryption_type']}")
        print(f"   Versioning: {result['versioning_status']}")
        print(f"   Logging: {result['logging_status']}")
        print(f"   Size: {result['size_status']}")
        
        if result['issues']:
            print(f"   Issues:")
            for issue in result['issues']:
                print(f"      ⚠️  {issue}")
    
    print("\n" + "=" * 100 + "\n")


def export_audit_csv(audit_results, output_file):
    """Export audit to CSV."""
    REPORTS_DIR.mkdir(exist_ok=True)
    csv_path = REPORTS_DIR / output_file
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'bucket_name', 'risk_level', 'is_public', 'encrypted',
            'versioning', 'logging', 'size_status', 'issues', 'creation_date'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in audit_results:
            row = {
                'bucket_name': result['bucket_name'],
                'risk_level': result['risk_level'],
                'is_public': 'YES' if result['is_public'] else 'NO',
                'encrypted': 'YES' if result['encrypted'] else 'NO',
                'versioning': 'YES' if result['versioning'] else 'NO',
                'logging': 'YES' if result['logging'] else 'NO',
                'size_status': result['size_status'],
                'issues': '; '.join(result['issues']),
                'creation_date': result['creation_date'].strftime('%Y-%m-%d') if result['creation_date'] else ''
            }
            writer.writerow(row)
    
    print(f"📁 Exported to: {csv_path}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="S3 Security Audit - Bucket security analyzer"
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run security audit (summary)"
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed audit results"
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
    logger.info("S3 Security Audit Started")
    logger.info("=" * 50)
    
    try:
        print("\n🔍 Connecting to AWS S3...")
        
        # Create S3 client
        s3 = get_s3_client()
        
        # List buckets
        buckets = list_buckets(s3, logger)
        
        if not buckets:
            print("\n✓ No S3 buckets found")
            print("\nℹ️  This is normal if you haven't created any buckets yet.")
            return
        
        print(f"📦 Found {len(buckets)} bucket(s). Running security audit...\n")
        
        # Audit each bucket
        audit_results = []
        for i, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            print(f"Auditing [{i}/{len(buckets)}]: {bucket_name}...", end="\r")
            
            result = audit_bucket(s3, bucket_name, logger)
            audit_results.append(result)
        
        print()  # New line after progress
        
        # If no flags, show summary by default
        if not any([args.audit, args.detailed, args.export]):
            args.audit = True
        
        # Display results
        if args.audit or args.export:
            print_audit_summary(audit_results)
        
        if args.detailed:
            print_detailed_audit(audit_results)
        
        if args.export:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_audit_csv(audit_results, f"s3_audit_{timestamp}.csv")
        
        logger.info(f"S3 Audit Completed - {len(buckets)} buckets audited")
        
    except KeyboardInterrupt:
        logger.warning("Audit cancelled")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Error: {e}")
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
