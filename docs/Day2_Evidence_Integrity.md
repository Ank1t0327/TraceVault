# Day 2: Evidence Integrity

## Features Implemented
- **File Hashing**: Added support for SHA-256, SHA-1, and MD5 file hashing.
- **Metadata Collection**: Automated extraction of Filename, Size, Creation Time, Modification Time, Access Time, Hash, and File Type.
- **Evidence Record Generation**: Created functionality to produce a structured JSON-like record containing Evidence ID, Hash, Timestamp, Source, Analyst, and Description.
- **CLI Updates**: 
  - `verify`: Calculates and verifies file hashes and displays metadata.
  - `record`: Generates and displays formal evidence records.

## Usage

```bash
# Verify evidence and show metadata
python3 tracevault.py verify evidence/disk_image.dd -m

# Create an evidence record
python3 tracevault.py record evidence/disk_image.dd --source "Server A" --analyst "Alice" --description "Malware disk image"
```
