# TraceVault — Digital Forensics & Incident Correlation Engine

TraceVault is a modular, high-performance Digital Forensics and Incident Investigation Engine. It transforms isolated system artifacts—such as authentication logs, browser history, file system modifications, and running processes—into structured attack chain narratives, automated risk scores, and executive forensic reports.

---

## 📌 Problem Statement
Digital forensics investigations often require analyzing disparate artifacts across multiple system layers. Security analysts face significant challenges manually correlating isolated log entries (e.g., SSH brute force attempts in `/var/log/auth.log`, file downloads in Chromium history, executable creation in `/tmp`, and reverse shell process execution). Without automated correlation:
- Critical attack vectors remain hidden in noise.
- Timeline reconstruction is error-prone and time-consuming.
- Evidence integrity and chain of custody risk compromise.

**TraceVault solves this problem** by providing an end-to-end automated pipeline that ingests raw evidence, verifies cryptographic hashes, extracts artifacts, scans for threat intelligence IOCs, correlates multi-stage attack chains, calculates cumulative risk scores, and exports executive-ready HTML and JSON reports.

---

## 🏗️ System Architecture

```text
                           TraceVault
                               │
               ┌───────────────┴───────────────┐
               ↓                               ↓
           Evidence                        Artifacts
       (Images/Files)               (Logs/Browser/Processes)
               │                               │
               └───────────────┬───────────────┘
                               ↓
                       Artifact Analysis
               (FileSystem / Chromium / Auth)
                               ↓
                         IOC Detection
               (Hashes / IPs / Domains / Proc)
                               ↓
                         Event Correlation
               (Attack Chain Sequence Generator)
                               ↓
                      Timeline Reconstruction
             (Unified Chronological Normalization)
                               ↓
                      Risk Scoring Algorithm
               (0-100 Score & Severity Rating)
                               ↓
                    Automated Report Generator
                     (reports/report.html & json)
```

---

## ⚡ Core Features & 10-Day Evolution

- **Day 1 — Foundation & Structure**: Built modular project architecture separating collectors, parsers, analyzers, utils, and reporting.
- **Day 2 — Evidence Integrity & Chain of Custody**: Cryptographic verification via multi-algorithm hashing (SHA-256, SHA-1, MD5), file metadata extraction, and JSON evidence record creation.
- **Day 3 — File System Analysis**: `FileSystemAnalyzer` for automated directory traversal, identifying hidden files, large files, recent modifications, executables, and suspicious filename extensions (e.g., double extensions, malware keywords).
- **Day 4 — Browser Forensics**: `ChromiumParser` to read SQLite history databases in read-only safe mode, converting WebKit microsecond timestamps into UTC datetime objects to extract visited URLs, search queries, and download logs.
- **Day 5 — System & User Activity**: Linux authentication log parsing (`/var/log/auth.log`), user account inspection (`/etc/passwd`), shell history (`.bash_history`), cron job persistence detection, and running process enumeration (`/proc`).
- **Day 6 — Timeline Engine**: Unified event schema (`Timestamp | Source | Event | Severity`), severity heuristics (`INFO` to `CRITICAL`), chronological sorting, and event deduplication.
- **Day 7 — Threat Intelligence & IOC Detection**: `IOCDetector` scanning system, process, network, and file artifacts against threat indicators (known malware hashes, double extensions, suspicious network IPs, backdoor root UID 0 accounts).
- **Day 8 — Investigation & Correlation Engine**: Automated attack chain reconstruction (`SSH Brute Force → Successful Login → Suspicious Download → Executable Created → Process Started`), cumulative risk scoring algorithm (0-100), and contributing risk reason tracking.
- **Day 9 — Forensic Report Generator**: `ReportGenerator` supporting structured JSON and glassmorphic dark-themed HTML report rendering with 6 executive sections.
- **Day 10 — Polish & Final Integration**: End-to-end `ForensicPipeline` integration, `CaseManager` evidence inventory tracking, edge-case testing suite (corrupt evidence, malformed logs, missing files, duplicate artifacts, large datasets), and complete CLI command suite.

---

## 📥 Installation

```bash
# Clone repository
git clone https://github.com/Ank1t0327/TraceVault.git
cd TraceVault

# Ensure Python 3.9+ is installed
python3 --version

# Run test suite to verify installation
pytest
```

---

## 🚀 CLI Usage Guide

### 1. Case & Evidence Management
```bash
# Create a new forensic investigation case
python tracevault.py case create CASE-2026-INC09 --investigator "Ankit" --description "Server Breach Incident"

# View active case metadata
python tracevault.py case show

# Add an evidence item to the case inventory with integrity hashing
python tracevault.py evidence add /path/to/evidence.dd --source "Server Hard Drive" --description "Primary OS Partition"
```

### 2. Evidence Verification & Hashing
```bash
# Calculate SHA-256, SHA-1, MD5 hashes and verify integrity
python tracevault.py verify /path/to/file.exe --metadata
```

### 3. File System Analysis
```bash
# Analyze directory artifacts with specific filters (executable, suspicious, hidden, recent, large)
python tracevault.py analyze /var/tmp --type suspicious
```

### 4. Specialized Parser Subcommands
```bash
# Analyze Chromium browser history and downloads
python tracevault.py browser

# Analyze system auth logs, user accounts, and running processes
python tracevault.py system

# Generate unified chronological timeline
python tracevault.py timeline

# Scan for Indicators of Compromise (IOCs)
python tracevault.py ioc

# Run attack sequence correlation and risk scoring
python tracevault.py correlate
```

### 5. Automated Reporting & Full Pipeline Run
```bash
# Run full end-to-end forensic analysis pipeline
python tracevault.py analyze .

# Export forensic investigation reports (HTML & JSON)
python tracevault.py report --format all --case-id "CASE-2026-INC09" --investigator "Ankit"
```

---

## 🔍 Sample Investigation Walkthrough

When running an end-to-end correlation analysis:
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

## 📊 Example Forensic Report Output (`reports/report.html`)

The generated HTML report features a modern glassmorphic dark interface containing:
1. **Case Information Header**: Case ID, Investigator, UTC Timestamp.
2. **Executive Summary**: Reconstructed threat narrative.
3. **Evidence Integrity Card**: Cryptographic SHA-256 hash digest, verification badge (`✓ VERIFIED`), and file metadata.
4. **Critical Findings Breakdown**: Color-coded badges for `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` findings.
5. **Chronological Timeline Table**: Timestamped sequence across `auth.log`, `browser`, `filesystem`, and `process` sources.
6. **IOC Threat Grid**: IP addresses, domains, file paths, and hashes with risk levels and reasons.

---

## 🧠 Technical Decisions

1. **Decoupled Architecture**: Parsers produce normalized data objects, separating evidence extraction from correlation logic. This allows seamless addition of new artifact parsers without refactoring the engine.
2. **Safe SQLite Database Locks**: `ChromiumParser` creates temporary read-only database copies before executing queries, preventing file locking conflicts during live system analysis.
3. **Heuristic Risk Scoring**: Risk score (0-100) is calculated via weighted forensic indicators (e.g., SSH brute force + success = +35 points, reverse shell execution = +40 points), giving immediate context to investigators.
4. **Resilience & Edge-Case Safety**: Log parsers and file analyzers gracefully handle malformed log lines, missing files, corrupted binaries, and unparseable dates without crashing the pipeline.

---

## ⚠️ Limitations

- **Platform Dependency**: System authentication log parsing is tuned for Linux (`/var/log/auth.log` and `/var/log/secure`). Windows Event Log parsing (`.evtx`) requires future extension.
- **SQLite History Dependencies**: Browser forensics currently targets Chromium-based browsers (Chrome, Chromium, Brave, Edge). Firefox SQLite schema support is planned.

---

## 🔮 Future Improvements

- **Graphviz / DOT Graph Export**: Render visual attack graph diagrams directly alongside the textual attack chain.
- **YARA Rule Integration**: Integrate YARA scanning for deep file payload signature identification.
- **Memory Forensics Parser**: Support Volatility dump analysis for RAM artifact extraction.