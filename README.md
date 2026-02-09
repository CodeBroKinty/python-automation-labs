# Python Automation Labs

A portfolio of practical Python automation scripts for system administration, cybersecurity, networking, and cloud operations.

## 📁 Repository Structure
```
python-automation-labs/
│
├── system_admin/          # System administration scripts
├── cybersecurity/         # Security automation tools
├── networking/            # Network scanning and monitoring
├── cloud_automation/      # AWS/cloud automation (coming soon)
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

#### 2. `day3_scan_folder.py` - Basic Folder Scanner
**What it does:**
- Scans a target directory
- Groups files by extension type
- Outputs results to `scan_report.txt`

**How to run:**
```bash
python system_admin/day3_scan_folder.py
```

#### 3. `day3_scan_folder_logged.py` - Advanced Folder Scanner
**What it does:**
- Everything from the basic scanner, plus:
- Logs all operations to `scan_folder.log`
- Handles missing/invalid folders gracefully
- Catches permission errors without crashing
- Optional report copying to another directory

**How to run:**
```bash
python system_admin/day3_scan_folder_logged.py
```

**Example scan_report.txt:**
```
=== Folder Scan Report ===
Timestamp: 2026-02-09 10:15:30
Folder: C:\Users\Kiante\python-automation-labs
Recursive: False
Total files found: 8

[.py] (3 files)
  - day3_scan_folder.py
  - day3_scan_folder_logged.py
  - system_info.py

[.md] (1 files)
  - README.md
```

## 🚀 Setup Instructions

### Prerequisites
- Python 3.10 or higher
- Git

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/<your-username>/python-automation-labs.git
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

## 📝 Skills Demonstrated

- ✅ Python fundamentals (variables, functions, loops, conditionals)
- ✅ File system operations (`os`, `pathlib`, `shutil`)
- ✅ Error handling (`try/except`)
- ✅ Logging configuration and best practices
- ✅ Code organization and modularity
- ✅ Git version control
- ✅ Professional documentation

## 🎯 Project Goals

This repository is being built as part of a structured learning path covering:
- **Week 1:** Python fundamentals + file operations ✅
- **Week 2:** System administration automation (in progress)
- **Week 3:** Cybersecurity tools (log parsing, threat detection)
- **Week 4:** Network automation (scanning, monitoring)
- **Week 5:** AWS cloud automation
- **Week 6:** Productivity tools + portfolio polish

## 📚 Learning Resources

- [Automate the Boring Stuff with Python](https://automatetheboringstuff.com/)
- [Python Official Documentation](https://docs.python.org/3/)
- CompTIA Security+ study materials

## 📄 License

This project is for educational and portfolio purposes.

---

**Note:** Generated files (`*.log`, `scan_report.txt`) are excluded from version control via `.gitignore`.