import sqlite3
import tempfile
import os
import pytest
from src.parsers.chromium import ChromiumParser, extract_urls_and_visits, extract_downloads, extract_search_terms, webkit_to_datetime

def create_mock_chromium_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "History")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url TEXT,
        title TEXT,
        visit_count INTEGER,
        typed_count INTEGER,
        last_visit_time INTEGER,
        hidden INTEGER
    );
    """)
    cursor.execute("""
    CREATE TABLE visits (
        id INTEGER PRIMARY KEY,
        url INTEGER,
        visit_time INTEGER
    );
    """)
    cursor.execute("""
    CREATE TABLE downloads (
        id INTEGER PRIMARY KEY,
        target_path TEXT,
        current_path TEXT,
        start_time INTEGER,
        total_bytes INTEGER,
        tab_url TEXT
    );
    """)

    # Insert sample data
    # Chrome WebKit time for ~ 14:31 UTC
    webkit_ts = 13300000000000000 
    cursor.execute("INSERT INTO urls VALUES (1, 'https://suspicious-site.com', 'Suspicious', 1, 0, ?, 0)", (webkit_ts,))
    cursor.execute("INSERT INTO visits VALUES (1, 1, ?)", (webkit_ts,))
    cursor.execute("INSERT INTO downloads VALUES (1, '/home/user/file.exe', '/home/user/file.exe', ?, 1024, 'https://download.example/file.exe')", (webkit_ts,))

    conn.commit()
    conn.close()
    return db_path

def test_webkit_timestamp():
    dt = webkit_to_datetime(13300000000000000)
    assert dt is not None

def test_chromium_parser_mock():
    db_path = create_mock_chromium_db()
    parser = ChromiumParser(history_db_path=db_path)
    results = parser.parse()
    
    assert "urls" in results
    assert len(results["urls"]) > 0
    assert results["urls"][0]["url"] == "https://suspicious-site.com"
    assert len(results["downloads"]) > 0
    assert results["downloads"][0]["filename"] == "file.exe"

def test_demo_fallback():
    parser = ChromiumParser(history_db_path="/non/existent/path/History")
    results = parser.parse()
    assert len(results["urls"]) > 0
    assert results["source"] == "Demonstration Artifacts"
