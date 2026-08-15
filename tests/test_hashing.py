import unittest
import os
from src.utils.hashing import calculate_hashes

class TestHashing(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_hash.txt"
        with open(self.test_file, "w") as f:
            f.write("test")
            
    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
            
    def test_calculate_hashes(self):
        hashes = calculate_hashes(self.test_file)
        self.assertIsNotNone(hashes)
        self.assertIn("SHA-256", hashes)
        self.assertIn("SHA-1", hashes)
        self.assertIn("MD5", hashes)
        self.assertEqual(hashes["SHA-256"], "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

if __name__ == "__main__":
    unittest.main()
