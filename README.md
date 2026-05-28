<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Security-orange?style=for-the-badge&logo=amazon-aws&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-18-red?style=for-the-badge)

**18 Production-Ready Security Automation Tools**

*Cloud Security | Network Scanning | Threat Detection | System Monitoring*

[🔗 Live Demo](#) • [📚 Documentation](#current-scripts) • [🚀 Quick Start](#setup-instructions)

</div>

---

# Python Automation Labs

A portfolio of practical Python automation scripts for system administration, cybersecurity, networking, and cloud operations.

## 📁 Repository Structure

```
python-automation-labs/
│
├── system_admin/          # System administration scripts
├── cybersecurity/         # Security automation tools
├── networking/            # Network scanning and monitoring
├── cloud_automation/      # AWS/cloud automation
├── productivity/          # Personal productivity tools (coming soon)
├── utils/                 # Shared utilities and helpers
│
├── requirements.txt
└── README.md
```

## 🛠️ Current Scripts

### System Administration (`system_admin/`)

#### 1. `system_info.py` - System Information Display
**What it does:**
- Displays OS name and version
- Shows current username
- Prints current working directory

**How to run:**
```bash
python system_admin/system_info.py
```

**Example output:**
```
=== SYSTEM INFORMATION ===
OS: Windows
OS Version: 11
Username: Kiante
Current Directory: C:\Users\Kiante\python-automation-labs
==========================
```

---

#### 2. `scan_folder_basic.py` - Basic Folder Scanner
**What it does:**
- Scans a target directory
- Groups files by extension type
- Outputs results to `scan_report.txt`

**How to run:**
```bash
python system_admin/scan_folder_basic.py
```

---

#### 3. `scan_folder.py` - Advanced Folder Scanner
**What it does:**
- Everything from the basic scanner, plus:
- Logs all operations to `scan_folder.log`
- Handles missing/invalid folders gracefully
- Catches permission errors without crashing
- Optional report copying to another directory

**How to run:**
```bash
python system_admin/scan_folder.py
```

**Example scan_report.txt:**
```
=== Folder Scan Report ===
Timestamp: 2026-02-09 10:15:30
Folder: C:\Users\Kiante\python-automation-labs
Recursive: False
Total files found: 8

[.py] (3 files)
  - scan_folder.py
  - scan_folder_basic.py
  - system_info.py

[.md] (1 files)
  - README.md
```

---

#### 4. `disk_monitor.py` - Disk Usage Monitor (Week 2)
**What it does:**
- Scans all available disk drives
- Calculates total, used, and free space
- Alerts if any drive exceeds 80% usage
- Logs all operations with timestamps

**Why it matters:**
- Prevents disk space issues before they cause problems
- Essential for system administration
- Foundation for automated monitoring systems

**How to run:**
```bash
python system_admin/disk_monitor.py --summary
```

**Example output:**
```
======================================================================
DISK USAGE REPORT
Timestamp: 2026-02-12 08:43:37
Alert Threshold: 80%
======================================================================

[OK] Drive: C:\
   Total:     953.04 GB
   Used:      320.01 GB
   Free:      633.04 GB
   Usage:     33.58%
   Status:    OK

======================================================================
```

---

#### 5. `file_integrity.py` - File Integrity Checker (Week 2)
**What it does:**
- Creates SHA-256 hash baselines of files
- Detects modifications, additions, and deletions
- Monitors unauthorized file changes
- Essential for security auditing and compliance

**Security+ relevance:**
- File integrity monitoring (FIM)
- Tamper detection
- Baseline configuration management

**How to run:**
```bash
# Create baseline
python system_admin/file_integrity.py --baseline <folder>

# Check for changes
python system_admin/file_integrity.py --check <folder>
```

**Example output:**
```
======================================================================
FILE INTEGRITY CHECK REPORT
Timestamp: 2026-02-10 13:48:25
======================================================================

⚠️  1 CHANGE(S) DETECTED

MODIFIED FILES (1):
  - file1.txt
    Baseline: a1b2c3d4e5f6...
    Current:  9z8y7x6w5v4u...

UNCHANGED: 1 files
======================================================================
```

---

#### 6. `process_monitor.py` - Process Monitor (Week 2)
**What it does:**
- Lists all running processes
- Shows top CPU and memory consumers
- Searches for specific processes
- Detects suspicious processes based on:
  - Process names (mimikatz, psexec, etc.)
  - Execution paths (temp folders, downloads)
  - High resource usage (CPU > 80%, Memory > 1GB)

**Security+ relevance:**
- Process monitoring for threat detection
- Anomaly detection
- Incident response

**How to run:**
```bash
# Show system summary
python system_admin/process_monitor.py --summary

# Top 10 CPU consumers
python system_admin/process_monitor.py --top 10

# Top 10 memory consumers
python system_admin/process_monitor.py --memory 10

# Search for a process
python system_admin/process_monitor.py --search chrome

# Detect suspicious processes
python system_admin/process_monitor.py --suspicious
```

**Example output:**
```
====================================================================================================
TOP 10 PROCESSES (BY CPU)
====================================================================================================
PID      Name                      CPU %    Memory MB    Threads    Status
----------------------------------------------------------------------------------------------------
31240    chrome.exe                124.3    1090.8       40         running
25972    chrome.exe                30.8     603.3        26         running
13724    TradingView.exe           15.6     665.5        23         running
====================================================================================================
```

---

### Cybersecurity (`cybersecurity/`)

#### 1. `log_parser.py` - Authentication Log Parser (Week 3)
**What it does:**
- Parses authentication logs (SSH, system logins)
- Counts failed login attempts per user and IP
- Identifies suspicious patterns
- Flags invalid username attempts

**Security+ relevance:**
- Log analysis and monitoring (Domain 2.4)
- Security incident detection
- Attack pattern recognition

**How to run:**
```bash
# Generate and parse sample log
python cybersecurity/log_parser.py --sample

# Parse actual log file
python cybersecurity/log_parser.py --file /var/log/auth.log
```

**Example output:**
```
⚠️  2 SUSPICIOUS USERS (≥5 failed logins)
   - root: 6 failed attempts
   - admin: 5 failed attempts

⚠️  SUSPICIOUS IP ADDRESSES (≥5 failed logins)
   - 192.168.1.100: 13 failed attempts
```

---

#### 2. `brute_force_detector.py` - Advanced Brute-Force Detection (Week 3)
**What it does:**
- **Velocity attacks**: Detects rapid-fire login attempts (X attempts in Y seconds)
- **Distributed attacks**: Identifies coordinated attacks from multiple IPs
- **Account enumeration**: Catches attackers testing multiple usernames
- Time-based pattern analysis with adjustable thresholds

**Security+ relevance:**
- Advanced threat detection (Domain 4.1)
- Incident response
- Attack pattern recognition

**How to run:**
```bash
# Analyze with default settings
python cybersecurity/brute_force_detector.py --sample

# Custom thresholds
python cybersecurity/brute_force_detector.py --sample --velocity 3 --window 30
```

**Example output:**
```
🚨 VELOCITY ATTACKS (2 detected)
   Rapid-fire login attempts from single source

   IP: 203.0.113.10
      Attempts: 10 in 60s
      Start: 14:30:10
      Targeted users: root, admin

🚨 DISTRIBUTED ATTACKS (1 detected)
   Target: admin
      Attack IPs: 5
      Total attempts: 11

🚨 ACCOUNT ENUMERATION (1 detected)
   Source IP: 192.0.2.50
      Usernames tested: 12
```

---

#### 3. `file_tamper_detector.py` - Advanced File Integrity Monitoring (Week 3)
**What it does:**
- Creates SHA-256 baselines with metadata tracking
- **Watch mode**: Continuously monitors files for changes
- Detects content modifications, permission changes, and size changes
- Tracks additions and deletions
- Critical system file protection

**Security+ relevance:**
- File integrity monitoring (FIM)
- Host-based intrusion detection
- Change management

**How to run:**
```bash
# Create baseline
python cybersecurity/file_tamper_detector.py --baseline <folder>

# Check for tampering
python cybersecurity/file_tamper_detector.py --check <folder>

# Real-time monitoring (watch mode)
python cybersecurity/file_tamper_detector.py --watch <folder> --interval 5

# Check critical system files
python cybersecurity/file_tamper_detector.py --critical
```

**Example output:**
```
⚠️  1 CHANGE(S) DETECTED

🔴 CONTENT MODIFIED (1 files)
   File: file1.txt
      Hash changed: bf65d03f943b0d96... → 801761f8ab9de26f...
      Time: 2026-02-23 12:01:03
```

---

#### 4. `security_reporter.py` - Professional Security Reporting (Week 3)
**What it does:**
- Generates multi-format reports from security logs
- **CSV export**: Excel-ready data analysis
- **Markdown reports**: Executive summaries with risk assessment
- **JSON export**: API/programmatic integration
- Automated risk scoring and recommendations

**Security+ relevance:**
- Security reporting and documentation
- Incident response documentation
- Executive communication

**How to run:**
```bash
# Generate all report formats
python cybersecurity/security_reporter.py --log-analysis sample_auth.log

# Specific format only
python cybersecurity/security_reporter.py --log-analysis sample_auth.log --format markdown
python cybersecurity/security_reporter.py --log-analysis sample_auth.log --format csv
python cybersecurity/security_reporter.py --log-analysis sample_auth.log --format json
```

**Generated reports:**
- `security_reports/failed_logins.csv` - All failed login attempts
- `security_reports/attack_summary.csv` - IP-based attack statistics
- `security_reports/security_report.md` - Comprehensive markdown report
- `security_reports/security_summary.json` - Structured data export

**Example Markdown report includes:**
- Executive summary with failure rates
- Risk assessment (CRITICAL/HIGH/MEDIUM/LOW)
- Ranked tables of attack sources
- Most targeted accounts
- Invalid username attempts
- Actionable recommendations

---

### Networking (`networking/`)

#### 1. `ping_sweep.py` - Network Host Discovery (Week 4)
**What it does:**
- Scans network ranges to find live hosts
- Supports CIDR notation (192.168.1.0/24), IP ranges, and single IPs
- Concurrent scanning with configurable thread pools
- Cross-platform (Windows, Linux, Mac)

**Security+ relevance:**
- Network reconnaissance (Domain 3.3)
- Asset discovery
- Network mapping

**How to run:**
```bash
# Scan single IP
python networking/ping_sweep.py --target 192.168.1.1

# Scan IP range
python networking/ping_sweep.py --target 192.168.1.1-192.168.1.50

# Scan entire subnet
python networking/ping_sweep.py --target 192.168.1.0/24

# Export results
python networking/ping_sweep.py --target 192.168.1.0/24 --output live_hosts.txt
```

**Example output:**
```
🔍 Scanning 254 host(s)...
Progress: 254/254 (100.0%)

✅ LIVE HOSTS (10)
   192.168.1.1     - Response time: 2ms
   192.168.1.5     - Response time: 5ms
   192.168.1.10    - Response time: 3ms
```

---

#### 2. `port_scanner.py` - TCP Port Scanner (Week 4)
**What it does:**
- Scans TCP ports to identify open services
- Fast concurrent scanning (100 threads by default)
- Common port presets and custom port ranges
- Service identification by port number
- Detects open, closed, and filtered ports

**Security+ relevance:**
- Vulnerability scanning (Domain 4.1)
- Service enumeration
- Attack surface analysis

**How to run:**
```bash
# Scan common ports
python networking/port_scanner.py --target 192.168.1.1 --common

# Scan specific ports
python networking/port_scanner.py --target 192.168.1.1 --ports 80,443,22,3306

# Scan port range
python networking/port_scanner.py --target 192.168.1.1 --range 1-1024

# Export results
python networking/port_scanner.py --target 192.168.1.1 --common --output scan_results.txt
```

**Example output:**
```
✅ OPEN PORTS (3)
   Port     Service              Status
   -------- -------------------- ----------
   22       SSH                  open
   80       HTTP                 open
   443      HTTPS                open

⏱️  Scan completed in 1.20 seconds
```

---

#### 3. `service_detector.py` - Banner Grabbing & Service Detection (Week 4)
**What it does:**
- Connects to open ports and grabs service banners
- Identifies service versions (OpenSSH 7.4, Apache 2.4, etc.)
- OS fingerprinting from service signatures
- Regex-based signature matching
- Detects vulnerabilities through version identification

**Security+ relevance:**
- Service enumeration (Domain 3.3)
- Vulnerability assessment
- OS fingerprinting

**How to run:**
```bash
# Detect services on specific ports
python networking/service_detector.py --target 192.168.1.1 --port 22,80,443

# Auto-scan common ports first, then detect
python networking/service_detector.py --target 192.168.1.1 --scan-first
```

**Example output:**
```
✅ DETECTED SERVICES
   Port     Service              Version/Details
   -------- -------------------- ----------------------------------------
   22       SSH                  OpenSSH 6.6.1
            OS Hint: Linux
   80       HTTP                 Apache 2.4.7
            OS Hint: Linux

📋 RAW BANNERS
   Port 22:
      SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

   Port 80:
      HTTP/1.1 200 OK
      Server: Apache/2.4.7 (Ubuntu)
```

---

#### 4. `network_scanner.py` - Unified Network Reconnaissance (Week 4)
**What it does:**
- Combines ping sweep, port scanning, and service detection
- Three scan modes: Quick (6 ports), Standard (16 ports), Deep (1024 ports)
- Comprehensive network assessment in one command
- Multi-format reporting (console, text, JSON)
- Concurrent host and port scanning

**Security+ relevance:**
- Complete network assessment
- Penetration testing workflow
- Security auditing

**How to run:**
```bash
# Quick scan (6 common ports)
python networking/network_scanner.py --target 192.168.1.0/24 --quick

# Standard scan (16 ports) - default
python networking/network_scanner.py --target 192.168.1.1

# Deep scan (first 1024 ports)
python networking/network_scanner.py --target 192.168.1.1 --deep

# Export comprehensive report
python networking/network_scanner.py --target 192.168.1.0/24 --export
```

**Example output:**
```
📊 OVERVIEW
   Live hosts discovered: 5
   Total open ports: 12

✅ DISCOVERED HOSTS

   📍 192.168.1.1
      Open ports: 3
      Ports: 22, 80, 443
      Services detected:
         22: SSH-2.0-OpenSSH_7.4
         80: HTTP/1.1 200 OK Server: nginx/1.18.0

📁 Reports saved:
   Text: network_scan_20260305_095050.txt
   JSON: network_scan_20260305_095050.json
```

---

### Cloud Automation (`cloud_automation/`)

#### 1. `ec2_inventory.py` - EC2 Instance Inventory (Week 5)
**What it does:**
- Lists all EC2 instances across your AWS account
- Extracts instance details (type, state, IPs, security groups)
- Security analysis (public IPs, default security groups, missing SSH keys)
- CSV export for asset management

**Security+ relevance:**
- Cloud asset inventory (Domain 2.2)
- Security group analysis
- Cloud security posture management

**How to run:**
```bash
# List all instances
python cloud_automation/ec2_inventory.py --list

# Detailed instance information
python cloud_automation/ec2_inventory.py --details

# Security check
python cloud_automation/ec2_inventory.py --security-check

# Export to CSV
python cloud_automation/ec2_inventory.py --export

# Different region
python cloud_automation/ec2_inventory.py --region us-west-2
```

**Example output:**
```
📊 SUMMARY
   Total instances: 3
   Running: 2
   Stopped: 1

📋 INSTANCES
   ID                   Name              Type          State      Public IP
   i-0abc123def456      web-server        t2.micro      running    54.123.45.67
   i-0def456abc789      database          t2.small      running    N/A
   i-0ghi789jkl012      backup            t2.micro      stopped    N/A
```

---

#### 2. `s3_security_audit.py` - S3 Bucket Security Audit (Week 5)
**What it does:**
- Scans all S3 buckets for security misconfigurations
- Detects public access (the #1 cause of S3 data breaches)
- Verifies encryption status (AES-256, KMS)
- Checks versioning and logging
- Risk scoring: CRITICAL → HIGH → MEDIUM → LOW

**Security+ relevance:**
- Cloud storage security (Domain 2.2)
- Data protection and encryption
- Compliance auditing

**Real-world impact:**
- Would have detected Capital One breach (100M+ records exposed)
- Prevents $100M+ data breach scenarios
- Implements AWS security best practices

**How to run:**
```bash
# Summary audit
python cloud_automation/s3_security_audit.py --audit

# Detailed analysis
python cloud_automation/s3_security_audit.py --detailed

# Export to CSV
python cloud_automation/s3_security_audit.py --export
```

**Example output:**
```
📊 SUMMARY
   Total buckets: 5
   Risk levels:
      🔴 CRITICAL: 1
      🟠 HIGH: 1
      🟡 MEDIUM: 2
      🟢 LOW: 1

🔴 CRITICAL RISK BUCKETS (1)
   customer-data-backup
      ⚠️  PUBLIC ACCESS ENABLED
      ⚠️  No encryption

🟠 HIGH RISK BUCKETS (1)
   application-logs
      ⚠️  No encryption
      ⚠️  Versioning disabled
```

---

#### 3. `iam_analyzer.py` - IAM Permission Analyzer (Week 5)
**What it does:**
- Lists all IAM users and analyzes permissions
- Detects missing MFA (Multi-Factor Authentication)
- Identifies users with admin access
- Finds unused access keys
- Group and policy analysis

**Security+ relevance:**
- Identity and access management (Domain 2.4)
- Least privilege principle
- Access control auditing

**Security checks:**
- ⚠️ Users without MFA (prevents account takeover)
- ⚠️ Admin access assignments
- ⚠️ Unused credentials (should be removed)
- ⚠️ Direct policy attachments (should use groups)

**How to run:**
```bash
# List all users
python cloud_automation/iam_analyzer.py --users

# Security analysis
python cloud_automation/iam_analyzer.py --security

# Export to CSV
python cloud_automation/iam_analyzer.py --export
```

**Example output:**
```
📊 SUMMARY
   Total users: 5
   Users with admin access: 1
   Users without MFA: 3

📋 USERS
   Username          Access Keys  MFA      Admin    Groups
   john.doe          2            ✓        ✓        2
   jane.smith        1            ✗        ✗        1
   backup-user       0            ✗        ✗        0

⚠️  SECURITY FINDINGS
   - 3 users without MFA enabled
   - 1 user with unused access keys (90+ days)
```

---

#### 4. `cost_monitor.py` - AWS Cost Monitor (Week 5)
**What it does:**
- Tracks current month AWS spending
- Cost breakdown by service (EC2, S3, Lambda, etc.)
- Monthly cost comparison and trends
- Cost forecasting (predicts month-end total)
- Identifies cost optimization opportunities

**Why it matters:**
- Prevents surprise AWS bills
- Many horror stories of $10k+ unexpected charges
- Cost visibility = cost control
- Essential for budget management

**How to run:**
```bash
# Current month cost
python cloud_automation/cost_monitor.py --current

# Cost by service
python cloud_automation/cost_monitor.py --by-service

# Monthly comparison
python cloud_automation/cost_monitor.py --comparison

# Cost forecast
python cloud_automation/cost_monitor.py --forecast

# Export report
python cloud_automation/cost_monitor.py --export
```

**Example output:**
```
💰 CURRENT SPENDING
   Period: 2026-03-01 to 2026-03-12
   Total: $47.82 USD
   Daily average: $3.99

📊 SERVICE BREAKDOWN
   Service                                  Cost         %
   Amazon Elastic Compute Cloud            $32.15      67.2%
   Amazon Simple Storage Service           $8.50       17.8%
   Amazon Virtual Private Cloud            $4.20        8.8%
   AWS Lambda                              $2.97        6.2%

📈 COST TREND
   Month        Cost         Change
   2026-01      $38.42       N/A
   2026-02      $43.17       +12.4%
   2026-03      $47.82       +10.8%

🔮 MONTH-END PROJECTION
   Current spending: $47.82
   Forecasted total: $125.60
   Remaining budget: $77.78
```

---

## 🔧 Configuration

All scripts use centralized configuration in `utils/config.py`.

### Modifying Settings

Edit `utils/config.py` to change script behavior:

```python
# Disk Monitor
DISK_ALERT_THRESHOLD = 80  # Change to 70 for earlier warnings

# Process Monitor  
PROCESS_CPU_THRESHOLD = 80.0
PROCESS_MEMORY_THRESHOLD = 1024

# Add suspicious process names
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz",
    "psexec",
    "your_malware.exe",  # Add custom entries
]
```

### Benefits of Centralized Config

- ✅ Change settings without editing code
- ✅ Consistent values across all scripts
- ✅ Easy to version control
- ✅ Clear documentation of all settings

---

## ☁️ AWS Setup

### Prerequisites
1. AWS account (Free Tier recommended)
2. AWS credentials configured

### Create AWS Access Keys
1. AWS Console → IAM → Users → [Your User]
2. Security credentials → Create access key
3. Choose "Command Line Interface (CLI)"
4. Download credentials

### Configure Credentials
```bash
# Windows
mkdir %USERPROFILE%\.aws
notepad %USERPROFILE%\.aws\credentials

# Add:
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
region = us-east-1
```

### Required IAM Permissions
Attach these policies to your IAM user:
- `AmazonEC2ReadOnlyAccess`
- `AmazonS3ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AWSBillingReadOnlyAccess`
- `CEFullAccess` (Cost Explorer)

**⚠️ Security Note:** Never commit AWS credentials to GitHub!

---

## 🚀 Setup Instructions

### Prerequisites
- Python 3.10 or higher
- Git

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/CodeBroKinty/python-automation-labs.git
cd python-automation-labs
```

2. **Create virtual environment:**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## 📦 Dependencies

Install required packages:
```bash
pip install -r requirements.txt
```

Current dependencies:
- `psutil` - System and process utilities
- `boto3` - AWS SDK for Python

---

## 📝 Skills Demonstrated

- ✅ Python fundamentals (variables, functions, loops, conditionals)
- ✅ File system operations (`os`, `pathlib`, `shutil`)
- ✅ Error handling (`try/except`)
- ✅ Logging configuration and best practices
- ✅ Code organization and modularity
- ✅ Git version control
- ✅ Professional documentation
- ✅ Cryptographic hashing (SHA-256)
- ✅ Process and system monitoring
- ✅ Configuration management
- ✅ Regular expressions and pattern matching
- ✅ Log parsing and analysis
- ✅ Time-based pattern detection
- ✅ Multi-format reporting (CSV, Markdown, JSON)
- ✅ Real-time monitoring with watch loops
- ✅ Advanced threat detection algorithms
- ✅ Security incident response
- ✅ Network reconnaissance and scanning
- ✅ Concurrent programming with ThreadPoolExecutor
- ✅ Socket programming (TCP connections)
- ✅ Banner grabbing and service fingerprinting
- ✅ CIDR notation and IP address manipulation
- ✅ Cross-platform networking
- ✅ AWS SDK (boto3) integration
- ✅ Cloud security auditing (S3, IAM)
- ✅ Cost monitoring and optimization
- ✅ Cloud asset inventory
- ✅ IAM permission analysis

---

## 🎯 Project Goals

This repository is being built as part of a structured learning path covering:
- **Week 1:** Python fundamentals + file operations ✅
- **Week 2:** System administration automation ✅
- **Week 3:** Cybersecurity tools (log parsing, threat detection) ✅
- **Week 4:** Network automation (scanning, monitoring) ✅
- **Week 5:** AWS cloud automation (EC2, S3, IAM, Cost) ✅

---

## 📚 Learning Resources

- [Automate the Boring Stuff with Python](https://automatetheboringstuff.com/)
- [Python Official Documentation](https://docs.python.org/3/)
- [AWS Documentation](https://docs.aws.amazon.com/)
- CompTIA Security+ study materials

---
