import datetime

def webkit_to_datetime(webkit_timestamp):
    """Convert WebKit/Chrome timestamp (microseconds since Jan 1, 1601) to datetime."""
    if not webkit_timestamp:
        return None
    try:
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch_start + datetime.timedelta(microseconds=int(webkit_timestamp))
    except (ValueError, OverflowError, TypeError):
        return None

def format_time_short(dt):
    """Format datetime object as HH:MM string."""
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%H:%M")
    return "00:00"

import os
import shutil
import sqlite3
import tempfile

def open_sqlite_readonly(db_path):
    """Safely open an SQLite database in read-only mode by creating a temp copy."""
    if not os.path.exists(db_path):
        return None
    
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "history_copy.db")
    try:
        shutil.copy2(db_path, temp_db_path)
        conn = sqlite3.connect(temp_db_path)
        conn.row_factory = sqlite3.Row
        return conn, temp_dir
    except Exception:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None

def extract_urls_and_visits(conn):
    """Query Chromium History database for visited URLs, titles, and timestamps."""
    query = """
    SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
    FROM visits
    JOIN urls ON visits.url = urls.id
    ORDER BY visits.visit_time ASC
    """
    records = []
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        for row in cursor.fetchall():
            dt = webkit_to_datetime(row["visit_time"])
            records.append({
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "timestamp": dt,
                "time_short": format_time_short(dt)
            })
    except sqlite3.Error:
        pass
    return records

def extract_downloads(conn):
    """Query Chromium History database for downloaded files."""
    query = """
    SELECT target_path, current_path, start_time, total_bytes, tab_url
    FROM downloads
    ORDER BY start_time ASC
    """
    downloads = []
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        for row in cursor.fetchall():
            dt = webkit_to_datetime(row["start_time"])
            path = row["target_path"] or row["current_path"] or ""
            downloads.append({
                "path": path,
                "filename": os.path.basename(path),
                "size_bytes": row["total_bytes"],
                "source_url": row["tab_url"],
                "timestamp": dt,
                "time_short": format_time_short(dt)
            })
    except sqlite3.Error:
        pass
    return downloads

from urllib.parse import parse_qs, urlparse

def extract_search_terms(conn_or_urls):
    """Extract search terms from URL query parameters (q, query, p, search)."""
    search_queries = []
    if isinstance(conn_or_urls, list):
        urls = conn_or_urls
    else:
        urls = extract_urls_and_visits(conn_or_urls)

    for item in urls:
        raw_url = item.get("url", "")
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
        for key in ["q", "query", "p", "search_query", "search"]:
            if key in params:
                for val in params[key]:
                    if val.strip():
                        search_queries.append({
                            "engine": parsed.netloc,
                            "term": val,
                            "timestamp": item.get("timestamp"),
                            "time_short": item.get("time_short", "00:00")
                        })
    return search_queries

class ChromiumParser:
    def __init__(self, history_db_path=None):
        self.history_db_path = history_db_path or self.find_default_history_path()

    @staticmethod
    def find_default_history_path():
        """Attempt to locate Chrome/Chromium history file on Linux/macOS/Windows."""
        home = os.path.expanduser("~")
        possible_paths = [
            os.path.join(home, ".config", "google-chrome", "Default", "History"),
            os.path.join(home, ".config", "chromium", "Default", "History"),
            os.path.join(home, "Library", "Application Support", "Google", "Chrome", "Default", "History"),
            os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    @staticmethod
    def convert_chrome_time(webkit_timestamp):
        return webkit_to_datetime(webkit_timestamp)

    def parse_history(self):
        return self.parse()

    def parse(self):
        """Parse browser history DB and return structured results."""
        if not self.history_db_path or not os.path.exists(self.history_db_path):
            return self.get_demo_data()

        conn, temp_dir = open_sqlite_readonly(self.history_db_path)
        if not conn:
            return self.get_demo_data()


        try:
            urls = extract_urls_and_visits(conn)
            downloads = extract_downloads(conn)
            searches = extract_search_terms(urls)
            return {
                "urls": urls,
                "downloads": downloads,
                "searches": searches,
                "source": self.history_db_path
            }
        finally:
            conn.close()
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def get_demo_data():
        """Provide fallback demonstration browser activity if no live history exists."""
        return {
            "urls": [
                {"url": "https://suspicious-site.com/login", "title": "Suspicious Site", "time_short": "14:31"},
                {"url": "https://download.example/file.exe", "title": "Index of /downloads", "time_short": "14:34"},
                {"url": "https://github.com/Ank1t0327/TraceVault", "title": "Ank1t0327/TraceVault", "time_short": "14:36"},
            ],
            "downloads": [
                {"filename": "file.exe", "path": "/Users/Test/Downloads/file.exe", "time_short": "14:34"}
            ],
            "searches": [
                {"engine": "google.com", "term": "how to clear forensic traces", "time_short": "14:30"}
            ],
            "source": "Demonstration Artifacts"
        }




