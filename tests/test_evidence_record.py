import unittest
from src.reporting.evidence_record import create_evidence_record

class TestEvidenceRecord(unittest.TestCase):
    def test_create_evidence_record(self):
        record = create_evidence_record(
            source="Test Source",
            analyst="Test Analyst",
            description="Test Description",
            primary_hash="test_hash_123"
        )
        self.assertIsNotNone(record)
        self.assertTrue(record["Evidence ID"].startswith("EV-"))
        self.assertEqual(record["Source"], "Test Source")
        self.assertEqual(record["Hash"], "test_hash_123")

if __name__ == "__main__":
    unittest.main()
