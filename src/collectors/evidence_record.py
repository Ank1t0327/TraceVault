import uuid
import json
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class EvidenceRecord:
    hash_sha256: str
    source: str
    description: str
    analyst: str = "Unknown"
    evidence_id: str = None
    timestamp: str = None
    metadata: dict = None
    hashes: dict = None

    def __post_init__(self):
        if self.evidence_id is None:
            self.evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=4)
