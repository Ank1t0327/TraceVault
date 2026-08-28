from dataclasses import dataclass, field
from typing import List, Dict, Any
import datetime

@dataclass
class ReportData:
    case_id: str = "CASE-2026-0801"
    investigator: str = "Lead Forensic Analyst"
    evidence_name: str = "disk_image.dd"
    date: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    
    # Evidence Integrity
    sha256: str = "8b7c4a1e99fa3829103bc492817491fa8b7c4a1e99fa3829103bc492817491fa"
    metadata: Dict[str, Any] = field(default_factory=lambda: {
        "Filename": "disk_image.dd",
        "Size": "4,294,967,296 bytes (4.0 GB)",
        "File Type": "RAW Disk Image / ELF Executable Container",
        "Created": "2026-08-25 10:00:00 UTC",
        "Modified": "2026-08-25 10:02:32 UTC",
        "Accessed": "2026-08-25 10:03:01 UTC"
    })
    integrity_status: str = "✓ VERIFIED (UNTAMPERED)"

    # Findings categorized by Severity
    findings: Dict[str, List[str]] = field(default_factory=lambda: {
        "CRITICAL": [
            "Reverse shell process launched (PID 4120: nc -e /bin/bash)",
            "Backdoor user account created with UID 0 privileges"
        ],
        "HIGH": [
            "SSH Brute Force attack detected from IP 192.168.1.105",
            "Suspicious executable file created in /tmp directory"
        ],
        "MEDIUM": [
            "Modification of scheduled system crontab tasks",
            "Execution of downloaded shell payload script"
        ],
        "LOW": [
            "File downloaded from untrusted web server",
            "Multiple interactive SSH session terminations"
        ]
    })


