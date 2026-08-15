import unittest
import os
from src.collectors.metadata import get_file_metadata

class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_meta.txt"
        with open(self.test_file, "w") as f:
            f.write("metadata test")
            
    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
            
    def test_get_file_metadata(self):
        metadata = get_file_metadata(self.test_file)
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["Filename"], "test_meta.txt")
        self.assertEqual(metadata["Size (bytes)"], 13)
        self.assertIn("Hashes", metadata)

if __name__ == "__main__":
    unittest.main()
