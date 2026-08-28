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

    # Timeline Events
    timeline: List[Dict[str, str]] = field(default_factory=lambda: [
        {"timestamp": "10:02:14 UTC", "event": "SSH authentication failure for user admin", "source": "auth.log"},
        {"timestamp": "10:02:18 UTC", "event": "SSH authentication failure for user admin", "source": "auth.log"},
        {"timestamp": "10:02:21 UTC", "event": "Successful SSH authentication for user admin", "source": "auth.log"},
        {"timestamp": "10:02:30 UTC", "event": "File payload.exe downloaded via Chromium", "source": "browser"},
        {"timestamp": "10:02:32 UTC", "event": "Executable /tmp/payload.exe created", "source": "filesystem"},
        {"timestamp": "10:03:01 UTC", "event": "Process PID 4120 (/tmp/payload.exe) executed", "source": "proc"}
    ])

    # Indicators of Compromise (IOCs)
    iocs: List[Dict[str, str]] = field(default_factory=lambda: [
        {"type": "IP", "value": "192.168.1.105", "risk": "HIGH", "reason": "SSH Brute Force Source"},
        {"type": "Domain", "value": "malicious-c2-server.com", "risk": "CRITICAL", "reason": "C2 Command & Control"},
        {"type": "Hash", "value": "44d88612fea8a8f36de82e1278abb02f", "risk": "HIGH", "reason": "Known Malware MD5"},
        {"type": "File", "value": "/tmp/payload.exe", "risk": "HIGH", "reason": "Unusual Executable Directory"}
    ])

    # Executive Investigation Summary
    summary: str = (
        "Analysis identified a sequence of failed authentication attempts followed by successful access "
        "and execution of a suspicious binary. The adversary gained access via SSH brute force from IP 192.168.1.105, "
        "downloaded an unverified payload (/tmp/payload.exe), and initiated a reverse shell process (PID 4120)."
    )

import json
import os

class ReportGenerator:
    def __init__(self, data: ReportData = None):
        self.data = data or ReportData()

    def to_dict(self) -> Dict[str, Any]:

        return {
            "case_information": {
                "case_id": self.data.case_id,
                "investigator": self.data.investigator,
                "evidence": self.data.evidence_name,
                "date": self.data.date
            },
            "evidence_integrity": {
                "sha256": self.data.sha256,
                "status": self.data.integrity_status,
                "metadata": self.data.metadata
            },
            "findings": self.data.findings,
            "timeline": self.data.timeline,
            "iocs": self.data.iocs,
            "investigation_summary": self.data.summary
        }

    def generate_json(self, output_path: str = "reports/report.json") -> str:
        """Export forensic investigation report as formatted JSON."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report_dict = self.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        return output_path






