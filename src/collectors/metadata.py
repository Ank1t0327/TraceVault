import os
import mimetypes
from datetime import datetime
from src.utils.hashing import calculate_hashes

def get_file_metadata(filepath):
    """Collects metadata and hashes for a given file."""
    if not os.path.exists(filepath):
        return None
        
    stat_info = os.stat(filepath)
    
    # Guess file type
    file_type, _ = mimetypes.guess_type(filepath)
    if not file_type:
        file_type = "Unknown"
        
    # Get hashes
    hashes = calculate_hashes(filepath)
    
    return {
        "Filename": os.path.basename(filepath),
        "Size (bytes)": stat_info.st_size,
        "Creation Time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
        "Modification Time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        "Access Time": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
        "File Type": file_type,
        "Hashes": hashes
    }
