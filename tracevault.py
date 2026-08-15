import argparse
import sys
import os
import json
from src.utils.hashing import calculate_hashes
from src.collectors.metadata import get_file_metadata
from src.reporting.evidence_record import create_evidence_record, display_evidence_record

def collect(args):
    print("Initializing acquisition phase...")
    print("Collecting digital evidence and maintaining chain of custody.")

def analyze(args):
    print("Initializing analysis phase...")
    print("Analyzing artifacts and verifying hashes.")

def report(args):
    print("Initializing reporting phase...")
    print("Generating comprehensive forensics report.")

def verify(args):
    print(f"Evidence: {os.path.basename(args.file)}\n")
    hashes = calculate_hashes(args.file)
    if hashes:
        print("SHA-256:")
        print(f"{hashes['SHA-256']}\n")
        print("Status:")
        print("✓ Evidence integrity recorded\n")
        
        if args.metadata:
            print("Metadata:")
            metadata = get_file_metadata(args.file)
            for k, v in metadata.items():
                if k != "Hashes":
                    print(f"{k}: {v}")
    else:
        print("File not found or unreadable.")

def record(args):
    metadata = get_file_metadata(args.file)
    if metadata and metadata["Hashes"]:
        primary_hash = metadata["Hashes"]["SHA-256"]
        rec = create_evidence_record(
            source=args.source,
            analyst=args.analyst,
            description=args.description,
            primary_hash=primary_hash
        )
        print("✓ Evidence record created:")
        display_evidence_record(rec)
    else:
        print("Failed to generate record. File not found.")

def main():
    parser = argparse.ArgumentParser(
        description="TraceVault: A Foundational Digital Forensics Toolkit",
        epilog="End of Day 2 - Evidence Integrity"
    )
    
    subparsers = parser.add_subparsers(title="commands", dest="command")
    
    # Collect command
    parser_collect = subparsers.add_parser("collect", help="Acquire and collect digital evidence")
    parser_collect.set_defaults(func=collect)
    
    # Analyze command
    parser_analyze = subparsers.add_parser("analyze", help="Analyze forensic artifacts and evidence")
    parser_analyze.set_defaults(func=analyze)
    
    # Report command
    parser_report = subparsers.add_parser("report", help="Generate forensic reports")
    parser_report.set_defaults(func=report)
    
    # Verify command
    parser_verify = subparsers.add_parser("verify", help="Verify evidence integrity and hashes")
    parser_verify.add_argument("file", help="File to verify")
    parser_verify.add_argument("-m", "--metadata", action="store_true", help="Include metadata")
    parser_verify.set_defaults(func=verify)
    
    # Record command
    parser_record = subparsers.add_parser("record", help="Create an evidence record")
    parser_record.add_argument("file", help="Evidence file")
    parser_record.add_argument("--source", required=True, help="Source of evidence")
    parser_record.add_argument("--analyst", required=True, help="Analyst name")
    parser_record.add_argument("--description", required=True, help="Description of evidence")
    parser_record.set_defaults(func=record)
    
    args = parser.parse_args()
    
    if args.command:
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
