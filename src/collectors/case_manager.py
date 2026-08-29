import os
import json
import datetime
from typing import Dict, Any, List
from src.utils.hashing import calculate_hashes
from src.utils.metadata import get_file_metadata

class CaseManager:
    """Manages forensic cases, case metadata, and evidence tracking."""
    def __init__(self, case_file: str = "evidence/case_meta.json"):
        self.case_file = case_file
        os.makedirs(os.path.dirname(case_file), exist_ok=True)
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.case_file):
            try:
                with open(self.case_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "case_id": "CASE-DEFAULT",
            "investigator": "Lead Analyst",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "description": "Default Forensic Investigation Case",
            "evidence_list": []
        }

    def _save(self):
        with open(self.case_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def create_case(self, case_id: str, investigator: str, description: str = "") -> Dict[str, Any]:
        """Initialize or overwrite a forensic case record."""
        self.data["case_id"] = case_id
        self.data["investigator"] = investigator
        self.data["created_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.data["description"] = description or f"Investigation Case {case_id}"
        self.data["evidence_list"] = []
        self._save()
        return self.data

    def add_evidence(self, file_path: str, source: str = "Disk Image", description: str = "") -> Dict[str, Any]:
        """Add an evidence item to the active case with integrity verification."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        hashes = calculate_hashes(file_path)
        meta = get_file_metadata(file_path)
        
        evidence_item = {
            "file": file_path,
            "source": source,
            "description": description or f"Evidence file {os.path.basename(file_path)}",
            "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sha256": hashes.get("sha256", "UNKNOWN") if hashes else "UNKNOWN",
            "size": meta.get("size", 0) if meta else 0,
            "integrity_verified": True if hashes else False
        }
        
        # Deduplicate evidence by file path
        self.data["evidence_list"] = [e for e in self.data["evidence_list"] if e["file"] != file_path]
        self.data["evidence_list"].append(evidence_item)
        self._save()
        return evidence_item

    def get_case_info(self) -> Dict[str, Any]:
        return self.data
