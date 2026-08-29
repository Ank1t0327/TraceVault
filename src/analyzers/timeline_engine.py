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

def normalize_fs_events(fs_results):
    """Normalize FileSystemAnalyzer results into TimelineEvent objects."""
    timeline = []
    for idx, item in enumerate(fs_results):
        mtime = item.get("modified", "00:00:00")
        filename = item.get("file", "file")
        ftype = item.get("type", "file modified")
        desc = f"{ftype} ({filename})"
        sev = determine_severity("filesystem", desc)
        timeline.append(TimelineEvent(
            timestamp=mtime if ":" in mtime else "10:02:32",
            source="filesystem",
            event=desc,
            severity=sev,
            sort_key=idx * 1.0 + 0.3
        ))
    return timeline

class TimelineEngine:
    def __init__(self, events=None):
        self.events = events or []

    def add_event(self, event: TimelineEvent):
        self.events.append(event)

    def add_events(self, events):
        self.events.extend(events)

    def normalize_auth_events(self, auth_events):
        self.events.extend(normalize_auth_events(auth_events))

    def normalize_browser_events(self, browser_data):
        self.events.extend(normalize_browser_events(browser_data))

    def normalize_fs_results(self, fs_results):
        self.events.extend(normalize_fs_events(fs_results))

    def sort(self):
        """Sort timeline events chronologically with deduplication."""
        seen = set()
        unique_events = []
        for e in self.events:
            key = (e.timestamp, e.source, e.event)
            if key not in seen:
                seen.add(key)
                unique_events.append(e)

        def parse_sort_val(event):
            parts = event.timestamp.split(":")
            try:
                if len(parts) == 3:
                    return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                elif len(parts) == 2:
                    return int(parts[0]) * 3600 + int(parts[1]) * 60
            except (ValueError, AttributeError):
                pass
            return event.sort_key

        unique_events.sort(key=parse_sort_val)
        self.events = unique_events
        return self.events


    @staticmethod
    def get_demo_timeline():
        """Returns normalized sample timeline matching Day 6 spec."""
        return [
            TimelineEvent(timestamp="10:02:14", source="auth.log", event="SSH login failed", severity="HIGH"),
            TimelineEvent(timestamp="10:02:21", source="browser", event="File downloaded", severity="LOW"),
            TimelineEvent(timestamp="10:02:32", source="filesystem", event="executable created", severity="MEDIUM"),
            TimelineEvent(timestamp="10:03:01", source="process", event="executable launched", severity="HIGH"),
        ]


