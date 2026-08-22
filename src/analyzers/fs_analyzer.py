import os
import time
import mimetypes

class FileSystemAnalyzer:
    def __init__(self, target_path):
        self.target_path = target_path

    @staticmethod
    def is_hidden(filepath):
        """Check if a file or directory is hidden."""
        basename = os.path.basename(filepath)
        return basename.startswith('.')

    @staticmethod
    def is_large_file(filepath, threshold_mb=50):
        """Check if file size exceeds threshold."""
        try:
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            return size_mb >= threshold_mb
        except OSError:
            return False

    @staticmethod
    def is_recently_modified(filepath, days=7):
        """Check if file was modified recently."""
        try:
            mtime = os.path.getmtime(filepath)
            current_time = time.time()
            return (current_time - mtime) <= (days * 86400)
        except OSError:
            return False

    @staticmethod
    def is_executable(filepath):
        """Check if a file is an executable (by extension or permission)."""
        executable_exts = {'.exe', '.dll', '.sh', '.bin', '.bat', '.cmd'}
        _, ext = os.path.splitext(filepath)
        if ext.lower() in executable_exts:
            return True
        return os.access(filepath, os.X_OK) and not os.path.isdir(filepath)

    @staticmethod
    def is_suspicious_filename(filepath):
        """Check for suspicious keywords in the filename."""
        suspicious_keywords = ['malware', 'hack', 'crack', 'payload', 'exploit', 'backdoor']
        basename = os.path.basename(filepath).lower()
        
        # Check double extensions (e.g. file.txt.exe)
        parts = basename.split('.')
        if len(parts) > 2 and parts[-1] in {'exe', 'bat', 'cmd', 'sh', 'vbs'}:
            return True
            
        for keyword in suspicious_keywords:
            if keyword in basename:
                return True
        return False



