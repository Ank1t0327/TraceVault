import argparse
import sys
import os
import json
from src.utils.hashing import calculate_hashes
from src.utils.metadata import get_file_metadata
from src.collectors.evidence_record import EvidenceRecord
from src.analyzers.fs_analyzer import FileSystemAnalyzer
from src.parsers.chromium import ChromiumParser

def browser_cmd(args):
    path = getattr(args, 'path', None)
    parser = ChromiumParser(history_db_path=path)
    data = parser.parse()

    print("Browser Activity\n")
    urls = data.get("urls", [])
    if urls:
        for item in urls:
            time_str = item.get("time_short", "00:00")
            raw_url = item.get("url", "")
            # Shorten or clean URL format for terminal display
            display_url = raw_url.replace("https://", "").replace("http://", "")
            print(f"{time_str}  {display_url}")
    else:
        print("No browser activity found.")


def collect(args):
    print("Initializing acquisition phase...")
    print("Collecting digital evidence and maintaining chain of custody.")

def analyze(args):
    analyzer = FileSystemAnalyzer(args.path)
    results = analyzer.run(filter_type=args.type)
    
    if not results:
        print("No interesting artifacts found.")
        return

    for res in results:
        print(f"[!] {os.path.basename(res['file'])}")
        print(f"    Location: {os.path.dirname(res['file'])}/")
        print(f"    Type: {res['type']}")
        print(f"    Modified: {res['modified']}\n")


def report(args):
    print("Initializing reporting phase...")
    print("Generating comprehensive forensics report.")

def verify(args):
    print(f"Evidence: {os.path.basename(args.file)}\n")
    hashes = calculate_hashes(args.file)
    if hashes:
        print("SHA-256:")
        print(f"{hashes['sha256']}\n")
        print("Status:")
        print("✓ Evidence integrity recorded\n")
        
        if args.metadata:
            print("Metadata:")
            metadata = get_file_metadata(args.file)
            for k, v in metadata.items():
                print(f"{k.capitalize()}: {v}")
    else:
        print("File not found or unreadable.")

def record(args):
    hashes = calculate_hashes(args.file)
    metadata = get_file_metadata(args.file)
    if hashes and metadata:
        primary_hash = hashes["sha256"]
        rec = EvidenceRecord(
            hash_sha256=primary_hash,
            source=args.source,
            analyst=args.analyst,
            description=args.description,
            metadata=metadata,
            hashes=hashes
        )
        print("✓ Evidence record created:")
        print(rec.to_json())
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
    parser_analyze.add_argument("path", help="Directory or file to analyze")
    parser_analyze.add_argument("--type", help="Filter by type (e.g., executable, hidden, suspicious, large, recent)")
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
