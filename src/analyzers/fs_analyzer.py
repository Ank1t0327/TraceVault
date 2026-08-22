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
