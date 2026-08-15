import uuid
from datetime import datetime

def create_evidence_record(source, analyst, description, primary_hash):
    """Creates a structured evidence record."""
    return {
        "Evidence ID": f"EV-{uuid.uuid4().hex[:8].upper()}",
        "Hash": primary_hash,
        "Timestamp": datetime.utcnow().isoformat() + "Z",
        "Source": source,
        "Analyst": analyst,
        "Description": description
    }
    
def display_evidence_record(record):
    """Displays an evidence record."""
    print(f"Evidence ID: {record['Evidence ID']}")
    print(f"Hash: {record['Hash']}")
    print(f"Timestamp: {record['Timestamp']}")
    print(f"Source: {record['Source']}")
    print(f"Analyst: {record['Analyst']}")
    print(f"Description: {record['Description']}")
