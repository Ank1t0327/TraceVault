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

    def generate_html(self, output_path: str = "reports/report.html") -> str:
        """Export forensic investigation report as a modern styled HTML document."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Build Findings HTML
        findings_html = ""
        severity_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6"
        }
        for sev, items in self.data.findings.items():
            if items:
                color = severity_colors.get(sev, "#6b7280")
                findings_html += f'<div style="margin-bottom:12px;"><span style="background:{color}; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{sev}</span><ul style="margin-top:6px; color:#d1d5db;">'
                for item in items:
                    findings_html += f'<li style="margin-bottom:4px;">{item}</li>'
                findings_html += '</ul></div>'

        # Build Timeline HTML
        timeline_rows = ""
        for evt in self.data.timeline:
            timeline_rows += f'''
            <tr style="border-bottom: 1px solid #374151;">
                <td style="padding: 10px; color: #9ca3af;">{evt.get("timestamp")}</td>
                <td style="padding: 10px; color: #f3f4f6;">{evt.get("event")}</td>
                <td style="padding: 10px; color: #60a5fa;"><code style="background:#1f2937; padding:2px 6px; border-radius:3px;">{evt.get("source")}</code></td>
            </tr>'''

        # Build IOC HTML
        ioc_rows = ""
        for ioc in self.data.iocs:
            risk_color = severity_colors.get(ioc.get("risk"), "#9ca3af")
            ioc_rows += f'''
            <tr style="border-bottom: 1px solid #374151;">
                <td style="padding: 10px; font-weight: bold; color: #f3f4f6;">{ioc.get("type")}</td>
                <td style="padding: 10px; color: #38bdf8; font-family: monospace;">{ioc.get("value")}</td>
                <td style="padding: 10px;"><span style="color:{risk_color}; font-weight:bold;">{ioc.get("risk")}</span></td>
                <td style="padding: 10px; color: #9ca3af;">{ioc.get("reason")}</td>
            </tr>'''

        # Build Metadata Table
        meta_html = ""
        for k, v in self.data.metadata.items():
            meta_html += f'<div style="display:flex; justify-content:space-between; border-bottom:1px solid #374151; padding:6px 0;"><span style="color:#9ca3af;">{k}:</span><span style="color:#f3f4f6; font-family:monospace;">{v}</span></div>'

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceVault Forensic Report - {self.data.case_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
            background: #1e293b;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            border: 1px solid #334155;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #334155;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 26px;
            color: #38bdf8;
        }}
        .section {{
            margin-bottom: 32px;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid #334155;
            padding-bottom: 8px;
            margin-bottom: 16px;
        }}
        .card {{
            background: #0f172a;
            border-radius: 8px;
            padding: 16px;
            border: 1px solid #334155;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #0f172a;
            color: #94a3b8;
            padding: 10px;
            font-size: 13px;
            text-transform: uppercase;
        }}
        .summary-box {{
            background: rgba(56, 189, 248, 0.1);
            border-left: 4px solid #38bdf8;
            padding: 16px;
            border-radius: 4px;
            color: #e2e8f0;
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>TraceVault Forensic Investigation Report</h1>
                <p style="color:#94a3b8; margin: 4px 0 0 0;">Case ID: <strong>{self.data.case_id}</strong></p>
            </div>
            <div style="text-align:right; color:#94a3b8; font-size:14px;">
                <p style="margin:0;">Investigator: <strong>{self.data.investigator}</strong></p>
                <p style="margin:4px 0 0 0;">Date: {self.data.date}</p>
            </div>
        </div>

        <div class="section">
            <div class="section-title">1. Executive Summary</div>
            <div class="summary-box">
                {self.data.summary}
            </div>
        </div>

        <div class="section">
            <div class="section-title">2. Evidence Integrity</div>
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <span style="color:#94a3b8;">SHA-256 Digest:</span>
                    <span style="font-family:monospace; color:#4ade80;">{self.data.sha256}</span>
                </div>
                <div style="color:#4ade80; font-weight:bold; margin-bottom:12px;">{self.data.integrity_status}</div>
                {meta_html}
            </div>
        </div>

        <div class="section">
            <div class="section-title">3. Critical Findings & Severity Breakdown</div>
            <div class="card">
                {findings_html}
            </div>
        </div>

        <div class="section">
            <div class="section-title">4. Chronological Timeline</div>
            <div class="card" style="padding:0; overflow:hidden;">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Description</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {timeline_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <div class="section-title">5. Indicators of Compromise (IOCs)</div>
            <div class="card" style="padding:0; overflow:hidden;">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Value / Indicator</th>
                            <th>Risk Level</th>
                            <th>Detection Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ioc_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>'''

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path







