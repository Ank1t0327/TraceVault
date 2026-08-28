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
    metadata: Dict[str, Any] = field(default_factory=dict)
    integrity_status: str = "✓ VERIFIED (UNTAMPERED)"
