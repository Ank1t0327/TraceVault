# TraceVault

TraceVault is a foundational Digital Forensics toolkit.

## Digital Forensics Core Concepts

Digital forensics involves the recovery and investigation of material found in digital devices, often in relation to computer crime.

### Evidence vs Artifacts
- **Evidence**: Data or physical items that can be presented in court to prove or disprove a fact.
- **Artifacts**: Objects or data created by the operating system or applications (e.g., registry keys, log files) that hold forensic value but may not directly prove a crime without context.

### The Forensics Process
1. **Acquisition**: The process of creating an exact duplicate (forensic image) of the original digital media.
2. **Preservation**: Ensuring the data is not altered or destroyed. This involves write-blockers and secure storage.
3. **Analysis**: Examining the acquired data to extract relevant information, using tools to parse artifacts and reconstruct events.
4. **Reporting**: Documenting the findings in a clear, concise, and reproducible manner.

### Hashing
Hashing (e.g., MD5, SHA-256) is used to verify data integrity. It acts as a digital fingerprint for files. If a file changes, its hash changes. We use hashing to prove that evidence has not been tampered with since acquisition.

### Chain of Custody
A chronological documentation or paper trail that records the sequence of custody, control, transfer, analysis, and disposition of evidence. It is critical for the admissibility of evidence in court.

## Project Structure
- `src/collectors/`: Modules for acquiring data.
- `src/analyzers/`: Modules for analyzing acquired data.
- `src/parsers/`: Modules for parsing specific artifacts.
- `src/utils/`: Helper functions (hashing, logging).
- `src/reporting/`: Modules for generating reports.
- `evidence/`: Directory to store acquired evidence.
- `reports/`: Directory to store generated reports.
- `tests/`: Unit tests.

## Usage
```bash
python tracevault.py --help
python tracevault.py collect
python tracevault.py analyze
python tracevault.py report
```

## Day 2: Evidence Integrity
- Implemented file hashing (SHA-256, SHA-1, MD5).
- Added metadata collection (Size, timestamps, types).
- Introduced Evidence Record generation.
- Added `verify` and `record` commands to CLI.

## Day 3: File System Analysis
- Implemented `FileSystemAnalyzer` for automated directory traversal.
- Added analysis capabilities for identifying hidden files and large files.
- Added detection for recently modified files and executables.
- Built a suspicious filename detector handling known malware keywords and double extensions.
- Added filtering support in `tracevault analyze --type <filter>` (e.g. `executable`, `suspicious`).

## Day 4: Browser Forensics
- Implemented Chromium browser history SQLite database parser (`ChromiumParser`).
- WebKit/Chrome 64-bit microsecond timestamp decoder to UTC datetimes.
- Safe read-only SQLite database connection handling for locked live browser files.
- Extracted URLs, visit counts, visit timestamps, page titles, download records, and search activity.
- Added `tracevault browser` CLI subcommand.

## Day 5: System & User Activity
- Implemented Linux SSH authentication log parser (`AuthLogParser`) for `/var/log/auth.log` and `/var/log/secure`.
- Extracted authentication timelines (failed SSH attempts, successful logins, invalid users, source IPs).
- Added shell history parser for `.bash_history` and `.zsh_history`.
- Added user account inspector parsing `/etc/passwd` to identify interactive users.
- Added cron job artifact parser (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs`).
- Added running process enumerator scanning `/proc`.
- Added `tracevault system` CLI subcommand to render Authentication Timelines and user activity.

## Day 6: Timeline Engine
- Implemented `TimelineEngine` (`src/analyzers/timeline_engine.py`) to unify multi-source forensic artifacts into a common schema: `Timestamp | Source | Event | Severity`.
- Added automated event normalizers for `auth.log`, `browser`, `filesystem`, and process execution events.
- Added heuristic severity assignment (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Implemented chronological event sorting mechanism.
- Added `tracevault timeline` CLI subcommand to allow investigators to reconstruct exact incident sequences.

## Day 7: Indicators of Compromise (IOCs)
- Implemented `IOCDetector` (`src/analyzers/ioc_detector.py`) with a lightweight Threat Intelligence engine.
- Added file & hash IOC matching for known malware hashes (MD5/SHA-256), executables in temporary paths (`/tmp`, `/dev/shm`), and double extension obfuscation.
- Added network IOC detection for brute force SSH IPs and suspicious URLs.
- Added system IOC detection for hacking processes (`nc`, `nmap`, `mimikatz`), backdoor root UID 0 accounts, and cron job persistence payloads.
- Added `tracevault ioc` CLI subcommand outputting structured IOC records (`Type`, `Value`, `Risk`, `Reason`).

## Day 8: Investigation & Correlation Engine
- Implemented `CorrelationEngine` (`src/analyzers/correlation_engine.py`) to connect isolated forensic findings into structured attack chains.
- Created attack graph sequence visualization (e.g. `SSH Brute Force → Successful Login → Suspicious Download → Executable Created → Process Started`).
- Built cumulative Risk Scoring algorithm (0-100) with severity ratings (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Added contributing risk reason tracking (`+ Multiple failed logins`, `+ Suspicious download`, `+ Executable execution`, `+ Persistence detected`).
- Added `tracevault correlate` CLI subcommand.

## Day 9 