from dataclasses import dataclass
import datetime

@dataclass
class TimelineEvent:
    timestamp: str  # Short time string HH:MM:SS or HH:MM
    source: str     # e.g., 'auth.log', 'browser', 'filesystem', 'process'
    event: str      # Event description
    severity: str   # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    sort_key: float = 0.0

    def to_line(self):
        return f"{self.timestamp} | {self.source} | {self.event} | {self.severity}"

def determine_severity(source, event_text):
    """Determine event severity level based on source and description heuristics."""
    text_lower = event_text.lower()
    if "fail" in text_lower or "invalid" in text_lower or "backdoor" in text_lower or "exploit" in text_lower:
        return "HIGH"
    if "executable" in text_lower or "malware" in text_lower or "process" in text_lower:
        return "MEDIUM"
    if "download" in text_lower or "hidden" in text_lower:
        return "LOW"
    return "INFO"
