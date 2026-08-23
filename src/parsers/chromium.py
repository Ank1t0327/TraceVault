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

