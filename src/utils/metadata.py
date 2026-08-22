import os
import mimetypes
from datetime import datetime

def format_timestamp(ts):
    """Convert a timestamp to a human-readable ISO format."""
    return datetime.fromtimestamp(ts).isoformat()

def get_file_metadata(filepath):
    """Extract metadata from a file."""
    if not os.path.exists(filepath):
        return None

    stat_info = os.stat(filepath)
    file_type, _ = mimetypes.guess_type(filepath)
    if file_type is None:
        file_type = "unknown"

    return {
        "filename": os.path.basename(filepath),
        "size": stat_info.st_size,
        "creation_time": format_timestamp(stat_info.st_ctime),
        "modification_time": format_timestamp(stat_info.st_mtime),
        "access_time": format_timestamp(stat_info.st_atime),
        "file_type": file_type
    }
