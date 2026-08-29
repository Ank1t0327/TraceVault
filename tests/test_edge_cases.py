import os
import json
import pytest
import tempfile
from src.collectors.case_manager import CaseManager
from src.analyzers.fs_analyzer import FileSystemAnalyzer
from src.parsers.auth_log import AuthLogParser
from src.parsers.chromium import ChromiumParser
from src.analyzers.timeline_engine import TimelineEngine, TimelineEvent
from src.analyzers.ioc_detector import IOCDetector
from src.analyzers.correlation_engine import CorrelationEngine
from src.analyzers.pipeline import ForensicPipeline

def test_corrupted_evidence(tmp_path):
    """Test handling of unreadable/corrupted evidence files."""
    corrupt_file = str(tmp_path / "corrupt_image.bin")
    with open(corrupt_file, "wb") as f:
        f.write(os.urandom(1024))
    
    cm = CaseManager(case_file=str(tmp_path / "case.json"))
    item = cm.add_evidence(corrupt_file, source="Corrupt USB", description="Binary garbage block")
    assert item["integrity_verified"] is True
    assert item["sha256"] != "UNKNOWN"

def test_missing_files(tmp_path):
    """Test graceful failure handling when target files do not exist."""
    cm = CaseManager(case_file=str(tmp_path / "case.json"))
    with pytest.raises(FileNotFoundError):
        cm.add_evidence(str(tmp_path / "non_existent_file.dd"))
    
    parser = AuthLogParser(log_path=str(tmp_path / "missing_auth.log"))
    events = parser.parse()
    assert events == []

    chrom_parser = ChromiumParser(history_db_path=str(tmp_path / "missing_history.sqlite"))
    history = chrom_parser.parse_history()
    assert "urls" in history



def test_malformed_logs(tmp_path):
    """Test resilience when parsing malformed or noisy log files."""
    malformed_log = str(tmp_path / "auth_corrupt.log")
    with open(malformed_log, "w", encoding="utf-8") as f:
        f.write("GARBAGE NOISE LINE 1234\n")
        f.write("Aug 25 10:02:14 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n")
        f.write("MORE NOISE NON PARSEABLE SYSTEM LOG LINE\n")
        f.write("Aug 25 10:02:21 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2\n")

    parser = AuthLogParser(log_path=malformed_log)
    events = parser.parse()
    assert len(events) == 2
    assert events[0]["event"] == "FAILED SSH LOGIN"
    assert events[1]["event"] == "SUCCESSFUL LOGIN"


def test_duplicate_artifacts():
    """Test deduplication of timeline events."""
    engine = TimelineEngine()
    e1 = TimelineEvent(timestamp="2026-08-25 10:00:00 UTC", source="auth.log", event="Failed login", severity="MEDIUM")
    e2 = TimelineEvent(timestamp="2026-08-25 10:00:00 UTC", source="auth.log", event="Failed login", severity="MEDIUM")
    
    engine.add_event(e1)
    engine.add_event(e2)
    sorted_events = engine.sort()
    
    # Verify deduplication
    assert len(sorted_events) == 1

def test_invalid_timestamps():
    """Test timeline and browser parsers handling invalid or unparseable timestamps."""
    parser = ChromiumParser()
    dt = parser.convert_chrome_time(None)
    assert dt is None
    dt_invalid = parser.convert_chrome_time("not_an_int")
    assert dt_invalid is None

    engine = TimelineEngine()
    e_invalid = TimelineEvent(timestamp="INVALID_DATE_STRING", source="fs", event="File edited", severity="LOW")
    engine.add_event(e_invalid)
    sorted_events = engine.sort()
    assert len(sorted_events) == 1
    assert sorted_events[0].timestamp == "INVALID_DATE_STRING"

def test_large_datasets(tmp_path):
    """Stress test FileSystemAnalyzer and TimelineEngine with thousands of items."""
    large_dir = tmp_path / "large_dir"
    large_dir.mkdir()
    
    # Create 500 test files
    for i in range(500):
        fname = large_dir / f"test_file_{i}.tmp"
        fname.write_text("sample content")

    analyzer = FileSystemAnalyzer(str(large_dir))
    results = analyzer.run()
    assert len(results) >= 500

    engine = TimelineEngine()
    engine.normalize_fs_results(results)
    sorted_events = engine.sort()
    assert len(sorted_events) >= 500

def test_pipeline_end_to_end(tmp_path):
    """Test complete ForensicPipeline execution end-to-end."""
    cm = CaseManager(case_file=str(tmp_path / "case.json"))
    cm.create_case("CASE-E2E", "Test Analyst", "E2E Test Case")
    
    pipeline = ForensicPipeline(case_manager=cm)
    res = pipeline.run(str(tmp_path))
    
    assert res["case_info"]["case_id"] == "CASE-E2E"
    assert "correlation" in res
    assert os.path.exists(res["reports"]["html"])
    assert os.path.exists(res["reports"]["json"])
