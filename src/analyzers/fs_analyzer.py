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

    def run(self, filter_type=None):
        """Analyze the target directory and filter by type."""
        results = []
        if not os.path.exists(self.target_path):
            return results

        if os.path.isfile(self.target_path):
            files = [self.target_path]
        else:
            files = []
            for root, _, filenames in os.walk(self.target_path):
                for f in filenames:
                    files.append(os.path.join(root, f))

        for filepath in files:
            is_suspicious = False
            flag = None

            if filter_type == 'hidden' and self.is_hidden(filepath):
                flag = 'Hidden file'
                is_suspicious = True
            elif filter_type == 'executable' and self.is_executable(filepath):
                flag = 'Executable'
                is_suspicious = True
            elif filter_type == 'large' and self.is_large_file(filepath):
                flag = 'Large file'
                is_suspicious = True
            elif filter_type == 'recent' and self.is_recently_modified(filepath):
                flag = 'Recently modified'
                is_suspicious = True
            elif filter_type == 'suspicious' and self.is_suspicious_filename(filepath):
                flag = 'Suspicious filename'
                is_suspicious = True
            elif filter_type == 'all':
                flag = 'File'
                is_suspicious = True
            elif filter_type is None:
                if self.is_suspicious_filename(filepath):
                    flag = 'Suspicious filename'
                    is_suspicious = True
                elif self.is_executable(filepath):
                    flag = 'Executable'
                    is_suspicious = True
                else:
                    flag = 'File'
                    is_suspicious = True


            if is_suspicious:
                results.append({
                    "file": filepath,
                    "type": flag,
                    "modified": time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(filepath)))
                })

        return results




