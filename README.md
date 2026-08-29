# TraceVault — Digital Forensics & Incident Correlation Engine

TraceVault is an enterprise-grade, modular Digital Forensics and Incident Investigation Engine. It transforms fragmented forensic artifacts—such as authentication logs, browser history, file system modifications, and running processes—into structured attack chain narratives, automated risk scores, and executive forensic reports.

---

## 📌 Problem Statement

Digital forensics investigations require analyzing disparate artifacts across multiple operating system layers. Security analysts face significant operational friction when manually correlating isolated log entries (e.g., SSH brute force attempts in `/var/log/auth.log`, browser payload downloads in Chromium history, executable creation in `/tmp`, and reverse shell process execution). 

Without automated incident correlation:
- Complex multi-stage attack vectors remain hidden in log noise.
- Timeline reconstruction is manual, slow, and error-prone.
- Evidence integrity and chain of custody risk compromise.

**TraceVault addresses this challenge** by providing a unified, end-to-end investigation pipeline that ingests raw digital evidence, verifies cryptographic integrity, extracts multi-layer artifacts, scans for threat intelligence indicators (IOCs), correlates attack sequences, computes dynamic risk scores, and exports executive-ready HTML and JSON reports.

---

## 🏗️ System Architecture

```text
                           TraceVault Engine
                                  │
               ┌──────────────────┴──────────────────┐
               ↓                                     ↓
        Case & Evidence                    System Artifacts
       (Images/Files/DBs)               (Logs/Browser/Processes)
               │                                     │
               └──────────────────┬──────────────────┘
                                  ↓
                          Artifact Analyzers
              (FileSystem / Chromium / AuthLog / UserProc)
                                  ↓
                        IOC Threat Detector
              (Hashes / IPs / Domains / Processes / Cron)
                                  ↓
                     Event Correlation Engine
               (Attack Chain Sequence Reconstruction)
                                  ↓
                       Unified Timeline Engine
                (Chronological Normalization & Deduplication)
                                  ↓
                        Dynamic Risk Scorer
                 (0-100 Score & Severity Breakdown)
                                  ↓
                    Automated Forensic Reporting
                     (reports/report.html & json)
```

---

## 🔥 Key Capabilities & Components

### 1. Evidence Management & Chain of Custody
- **Cryptographic Hash Verification**: Calculates MD5, SHA-1, and SHA-256 digests to ensure strict data preservation and tamper detection.
- **File Metadata Extraction**: Collects POSIX file attributes, exact file sizes, MIME types, and MACB timestamps (Modified, Accessed, Created).
- **Case Inventory Management**: `CaseManager` creates and manages structured forensic case records (`evidence/case_meta.json`) tracking evidence items and analysts.

### 2. File System Analysis
- **Automated Directory Traversal**: Recursive filesystem inspection targeting hidden files, large files (>50MB), and recently modified artifacts.
- **Suspicious File Detector**: Heuristic scanner identifying known malware keywords (`payload`, `exploit`, `backdoor`, `crack`) and double-extension obfuscation (e.g., `invoice.pdf.exe`).
- **Filtering Engine**: Filter file artifacts by type (`executable`, `suspicious`, `hidden`, `recent`, `large`).

### 3. Browser Forensics
- **Chromium SQLite Parser**: Extract browsing history, page titles, visit counts, search terms, and download records from Chrome, Chromium, Brave, and Edge.
- **WebKit Timestamp Decoder**: Converts 64-bit microsecond WebKit timestamps into UTC datetime formats.
- **Safe Read-Only Locks**: Copies locked SQLite databases to temporary environments before executing queries to prevent file locking conflicts.

### 4. System & User Activity Analysis
- **SSH Authentication Log Parser**: Extracts login attempts, failed password brute force series, invalid users, and source IP addresses from `/var/log/auth.log` and `/var/log/secure`.
- **User & Process Inspection**: Enumerates interactive accounts (`/etc/passwd`), active shell history (`.bash_history`, `.zsh_history`), and running system processes (`/proc`).
- **Persistence Detection**: Inspects cron job directories (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron`) for backdoor schedule entries.

### 5. Unified Timeline Engine
- **Normalizer**: Standardizes disparate log formats into a common schema: `Timestamp | Source | Event | Severity`.
- **Heuristic Severity Rating**: Assigns threat levels (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Chronological Sorting & Deduplication**: Sorts multi-source events sequentially and eliminates duplicate entries.

### 6. Threat Intelligence & IOC Detection
- **Multi-Vector Threat Scanning**: Matches file hashes against known malware databases, identifies suspicious process execution (e.g., `nc -e /bin/bash`, `mimikatz`), flags malicious network IPs/domains, and detects backdoor root accounts (UID 0).

### 7. Attack Correlation & Risk Scoring Engine
- **Sequence Reconstruction**: Connects isolated events into chronological attack chains (e.g., `SSH Brute Force → Successful Login → Suspicious Download → Executable Created → Process Started`).
- **Cumulative Risk Algorithm**: Calculates dynamic risk scores (0-100) and severity ratings based on weighted threat indicators.
- **Contributing Factors**: Tracks specific risk reasons (`+ Multiple failed logins`, `+ Suspicious download`, `+ Persistence detected`).

### 8. Executive Forensic Reporting
- **Glassmorphic HTML Reports**: Renders responsive dark-theme reports (`reports/report.html`) complete with case information, evidence integrity badges, severity breakdowns, chronological timelines, and IOC tables.
- **Structured JSON Export**: Exports machine-readable report data (`reports/report.json`) for SIEM integration.

---

## 📁 Repository Structure

```text
TraceVault/
├── tracevault.py               # Main CLI Entrypoint
├── src/
│   ├── collectors/             # Evidence & Case Management
│   │   ├── case_manager.py
│   │   └── evidence_record.py
│   ├── parsers/                # Specialized Artifact Parsers
│   │   ├── auth_log.py
│   │   ├── chromium.py
│   │   ├── system_info.py
│   │   └── user_activity.py
│   ├── analyzers/              # Forensics, IOC & Correlation Engines
│   │   ├── fs_analyzer.py
│   │   ├── ioc_detector.py
│   │   ├── correlation_engine.py
│   │   ├── timeline_engine.py
│   │   └── pipeline.py
│   ├── reporting/              # HTML & JSON Report Generators
│   │   └── report_generator.py
│   └── utils/                  # Cryptographic Hashing & Metadata
│       ├── hashing.py
│       └── metadata.py
├── evidence/                   # Evidence Storage & Case Inventories
├── reports/                    # Generated Forensic Reports
└── tests/                      # Automated Unit & Resilience Test Suite
```

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/Ank1t0327/TraceVault.git
cd TraceVault

# Verify Python version (Python 3.9+ required)
python3 --version

# Run full test suite
pytest
```

---

## 🚀 CLI Usage Guide

### 1. Case & Evidence Management
```bash
# Create a new investigation case
python tracevault.py case create CASE-2026-INC09 --investigator "Ankit" --description "Server Intrusion Case"

# Show active case details
python tracevault.py case show

# Add evidence file to active case inventory
python tracevault.py evidence add /path/to/evidence.dd --source "Primary Server Disk"
```

### 2. Evidence Verification & Hashing
```bash
# Verify cryptographic hashes (SHA-256, SHA-1, MD5) and POSIX metadata
python tracevault.py verify /path/to/suspicious_file.exe --metadata
```

### 3. File System Analysis
```bash
# Analyze directory artifacts with type filtering
python tracevault.py analyze /var/tmp --type suspicious
```

### 4. Specialized Forensics Commands
```bash
# Analyze Chromium browser history and downloads
python tracevault.py browser

# Analyze Linux authentication logs and user activity
python tracevault.py system

# Reconstruct unified chronological timeline
python tracevault.py timeline

# Scan for Indicators of Compromise (IOCs)
python tracevault.py ioc

# Run attack sequence correlation and risk scoring
python tracevault.py correlate
```

### 5. End-to-End Investigation Pipeline
```bash
# Run complete multi-artifact forensic pipeline
python tracevault.py analyze .

# Export forensic reports (HTML & JSON)
python tracevault.py report --format all --case-id "CASE-2026-INC09" --investigator "Ankit"
```

---

## 🔍 Sample CLI Investigation Output

```bash
$ python tracevault.py analyze .

[*] Starting TraceVault Forensic Analysis on target: .

--- Artifact Analysis Summary ---
[!] payload.exe (Executable)

--- Attack Correlation & Risk Assessment ---
Attack Chain: SSH Brute Force → Successful Login → Suspicious File Download → Executable Created → Process Started
Risk Score: 87/100 (HIGH Severity)

✓ Reports Generated Successfully:
  HTML: reports/report.html
  JSON: reports/report.json
```

---

## 🧪 Testing & Resilience

TraceVault includes a comprehensive test suite (`pytest`) validating both unit logic and system resilience under edge-case conditions:
- **Corrupt Evidence**: Validates hashing and parsing behavior on binary garbage data.
- **Missing Files**: Graceful error handling and empty data fallback when targets are absent.
- **Malformed Logs**: Resilient regex parsing over corrupted or noisy system log lines.
- **Duplicate Artifacts**: Automatic event deduplication in timeline reconstruction.
- **Invalid Timestamps**: Safe handling of unparseable date strings and Chrome microsecond stamps.
- **Large Datasets**: Stress testing filesystem analysis and timeline engines against 500+ artifacts.

---

## 🧠 Technical Decisions

1. **Decoupled Architecture**: Artifact parsers produce normalized data structures, separating data collection from correlation logic. This allows easy addition of new artifact parsers without altering the core pipeline.
2. **Safe SQLite Locks**: `ChromiumParser` creates temporary read-only database copies before running queries, preventing database lock conflicts on active systems.
3. **Heuristic Severity & Risk Calibration**: Dynamic risk scores (0-100) are computed via weighted threat vectors, giving immediate operational context to incident responders.

---

## ⚠️ Limitations & Future Improvements

- **Linux-Centric Auth Parsing**: Authentication log parsing currently targets POSIX `/var/log/auth.log`. Extension to Windows Event Logs (`.evtx`) is planned.
- **Graphviz Visual Graph Export**: Planned feature to output SVG/PNG attack graph diagrams alongside textual sequences.
- **YARA Signature Integration**: Future support for YARA rule scanning across file payloads.