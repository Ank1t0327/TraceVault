from src.analyzers.timeline_engine import TimelineEngine, TimelineEvent, determine_severity, normalize_auth_events, normalize_browser_events

def test_determine_severity():
    assert determine_severity("auth.log", "SSH login failed") == "HIGH"
    assert determine_severity("browser", "File downloaded") == "LOW"
    assert determine_severity("filesystem", "executable created") == "MEDIUM"
    assert determine_severity("process", "executable launched") == "MEDIUM"

def test_timeline_sorting():
    engine = TimelineEngine()
    engine.add_events([
        TimelineEvent(timestamp="10:03:01", source="process", event="executable launched", severity="HIGH"),
        TimelineEvent(timestamp="10:02:14", source="auth.log", event="SSH login failed", severity="HIGH"),
        TimelineEvent(timestamp="10:02:21", source="browser", event="File downloaded", severity="LOW"),
        TimelineEvent(timestamp="10:02:32", source="filesystem", event="executable created", severity="MEDIUM"),
    ])
    sorted_events = engine.sort()
    timestamps = [e.timestamp for e in sorted_events]
    assert timestamps == ["10:02:14", "10:02:21", "10:02:32", "10:03:01"]

def test_demo_timeline():
    events = TimelineEngine.get_demo_timeline()
    assert len(events) == 4
    assert events[0].timestamp == "10:02:14"
    assert events[0].source == "auth.log"
    assert events[1].source == "browser"
    assert events[2].source == "filesystem"
    assert events[3].source == "process"
