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

def normalize_auth_events(auth_events):
    """Normalize AuthLogParser events into TimelineEvent objects."""
    timeline = []
    for idx, evt in enumerate(auth_events):
        ts_str = evt.get("time", "00:00:00")
        event_desc = evt.get("event", "Auth Event")
        if evt.get("user"):
            event_desc += f" (User: {evt['user']})"
        sev = determine_severity("auth.log", event_desc)
        timeline.append(TimelineEvent(
            timestamp=ts_str,
            source="auth.log",
            event=event_desc,
            severity=sev,
            sort_key=idx * 1.0
        ))
    return timeline

def normalize_browser_events(browser_data):
    """Normalize ChromiumParser outputs into TimelineEvent objects."""
    timeline = []
    urls = browser_data.get("urls", [])
    downloads = browser_data.get("downloads", [])

    for idx, item in enumerate(urls):
        ts_str = item.get("time_short", "00:00")
        if len(ts_str) == 5:
            ts_str += ":00"
        url = item.get("url", "")
        desc = f"Visited {url}"
        sev = determine_severity("browser", desc)
        timeline.append(TimelineEvent(
            timestamp=ts_str,
            source="browser",
            event=desc,
            severity=sev,
            sort_key=idx * 1.0 + 0.1
        ))

    for idx, item in enumerate(downloads):
        ts_str = item.get("time_short", "00:00")
        if len(ts_str) == 5:
            ts_str += ":00"
        filename = item.get("filename") or item.get("path", "file")
        desc = f"File downloaded ({filename})"
        sev = determine_severity("browser", desc)
        timeline.append(TimelineEvent(
            timestamp=ts_str,
            source="browser",
            event=desc,
            severity=sev,
            sort_key=idx * 1.0 + 0.2
        ))
    return timeline

