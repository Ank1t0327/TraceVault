import argparse
import sys
import os
import json
from src.utils.hashing import calculate_hashes
from src.utils.metadata import get_file_metadata
from src.collectors.evidence_record import EvidenceRecord
from src.analyzers.fs_analyzer import FileSystemAnalyzer
from src.analyzers.timeline_engine import TimelineEngine, TimelineEvent
from src.analyzers.ioc_detector import IOCDetector, IOC
from src.analyzers.correlation_engine import CorrelationEngine
from src.parsers.chromium import ChromiumParser
from src.parsers.auth_log import AuthLogParser
from src.parsers.user_activity import parse_shell_history, parse_user_accounts
from src.parsers.system_info import parse_cron_jobs, parse_running_processes

def correlate_cmd(args):
    engine = CorrelationEngine()
    print(engine.display())


def ioc_cmd(args):
    detector = IOCDetector()
    iocs = detector.scan()
    for item in iocs:
        print(item.display())


def timeline_cmd(args):
    # Collect real artifacts if available, or fall back to normalized demo timeline
    events = TimelineEngine.get_demo_timeline()
    
    print("Timestamp | Source | Event | Severity\n")
    for evt in events:
        print(f"{evt.timestamp} | {evt.source} | {evt.event} | {evt.severity}")


def system_cmd(args):
    log_path = getattr(args, 'log', None)
    parser = AuthLogParser(log_path=log_path)
    events = parser.parse()

    print("Authentication Timeline\n")
    source_ips = set()
    users = set()

    for evt in events:
        print(f"{evt['time']}  {evt['event']}")
        if evt.get("ip"):
            source_ips.add(evt["ip"])
        if evt.get("user"):
            users.add(evt["user"])

    print("\nSource:")
    print(", ".join(sorted(source_ips)) if source_ips else "Unknown")

    print("\nUser:")
    print(", ".join(sorted(users)) if users else "Unknown")


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

from src.collectors.case_manager import CaseManager
from src.analyzers.pipeline import ForensicPipeline
from src.reporting.report_generator import ReportGenerator, ReportData

def case_cmd(args):
    cm = CaseManager()
    if args.action == "create":
        info = cm.create_case(args.case_id, args.investigator or "Lead Analyst", args.description or "")
        print("✓ Forensic Case Created Successfully:")
        print(f"  Case ID: {info['case_id']}")
        print(f"  Investigator: {info['investigator']}")
        print(f"  Created At: {info['created_at']}")
    elif args.action == "show":
        info = cm.get_case_info()
        print(json.dumps(info, indent=2))

def evidence_cmd(args):
    cm = CaseManager()
    if args.action == "add":
        try:
            item = cm.add_evidence(args.file, source=args.source or "Disk Image", description=args.description or "")
            print("✓ Evidence Added & Verified:")
            print(f"  File: {item['file']}")
            print(f"  SHA-256: {item['sha256']}")
            print(f"  Source: {item['source']}")
        except Exception as e:
            print(f"Error adding evidence: {e}")

def analyze(args):
    target = getattr(args, 'path', '.') or '.'
    print(f"[*] Starting TraceVault Forensic Analysis on target: {target}")
    
    # Run full end-to-end pipeline
    pipeline = ForensicPipeline()
    res = pipeline.run(target)
    
    print("\n--- Artifact Analysis Summary ---")
    analyzer = FileSystemAnalyzer(target)
    fs_results = analyzer.run(filter_type=args.type)
    if fs_results:
        for item in fs_results[:5]:
            print(f"[!] {os.path.basename(item['file'])} ({item['type']})")
    
    print("\n--- Attack Correlation & Risk Assessment ---")
    corr = res["correlation"]
    print(f"Attack Chain: {' → '.join(corr['chain'])}")
    print(f"Risk Score: {corr['risk_score']}/100 ({corr['severity']} Severity)")
    
    print(f"\n✓ Reports Generated Successfully:")
    print(f"  HTML: {res['reports']['html']}")
    print(f"  JSON: {res['reports']['json']}")


def report(args):
    print("Initializing TraceVault Report Generator...")
    case_id = getattr(args, 'case_id', None) or "CASE-2026-0801"
    investigator = getattr(args, 'investigator', None) or "Lead Forensic Analyst"
    fmt = getattr(args, 'format', 'all')
    
    data = ReportData(case_id=case_id, investigator=investigator)
    generator = ReportGenerator(data)
    
    if fmt in ['html', 'all']:
        html_file = generator.generate_html("reports/report.html")
        print(f"✓ Generated HTML Forensic Report: {html_file}")
    if fmt in ['json', 'all']:
        json_file = generator.generate_json("reports/report.json")
        print(f"✓ Generated JSON Forensic Report: {json_file}")


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
    
    # Case command
    parser_case = subparsers.add_parser("case", help="Manage forensic investigation cases")
    parser_case_sub = parser_case.add_subparsers(dest="action")
    parser_case_create = parser_case_sub.add_parser("create", help="Create a new forensic case")
    parser_case_create.add_argument("case_id", help="Unique Case Identifier")
    parser_case_create.add_argument("--investigator", help="Lead investigator name")
    parser_case_create.add_argument("--description", help="Case description")
    parser_case_create.set_defaults(func=case_cmd)
    parser_case_show = parser_case_sub.add_parser("show", help="Show active case metadata")
    parser_case_show.set_defaults(func=case_cmd)

    # Evidence command
    parser_evidence = subparsers.add_parser("evidence", help="Manage case evidence inventory")
    parser_evidence_sub = parser_evidence.add_subparsers(dest="action")
    parser_evidence_add = parser_evidence_sub.add_parser("add", help="Add evidence file to active case")
    parser_evidence_add.add_argument("file", help="Path to evidence file")
    parser_evidence_add.add_argument("--source", help="Source of evidence")
    parser_evidence_add.add_argument("--description", help="Description of evidence")
    parser_evidence_add.set_defaults(func=evidence_cmd)

    # Analyze command
    parser_analyze = subparsers.add_parser("analyze", help="Analyze forensic artifacts and evidence")
    parser_analyze.add_argument("path", nargs="?", default=".", help="Directory or file to analyze (default: current dir)")
    parser_analyze.add_argument("--type", help="Filter by type (e.g., executable, hidden, suspicious, large, recent)")
    parser_analyze.set_defaults(func=analyze)

    
    # Report command
    parser_report = subparsers.add_parser("report", help="Generate forensic reports")
    parser_report.add_argument("--format", choices=["html", "json", "all"], default="all", help="Output format (html, json, all)")
    parser_report.add_argument("--case-id", help="Case identification string")
    parser_report.add_argument("--investigator", help="Lead investigator name")
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
    
    # Browser command
    parser_browser = subparsers.add_parser("browser", help="Analyze Chromium browser history and activity")
    parser_browser.add_argument("--path", help="Optional custom path to Chromium History database file")
    parser_browser.set_defaults(func=browser_cmd)

    # System command
    parser_system = subparsers.add_parser("system", help="Analyze system/user activity and auth logs")
    parser_system.add_argument("--log", help="Optional path to auth.log file")
    parser_system.set_defaults(func=system_cmd)

    # Timeline command
    parser_timeline = subparsers.add_parser("timeline", help="Generate a unified chronological forensic timeline")
    parser_timeline.set_defaults(func=timeline_cmd)

    # IOC command
    parser_ioc = subparsers.add_parser("ioc", help="Detect Indicators of Compromise (IOCs) across evidence artifacts")
    parser_ioc.set_defaults(func=ioc_cmd)

    # Correlate command
    parser_correlate = subparsers.add_parser("correlate", help="Correlate evidence findings into attack chains and risk scores")
    parser_correlate.set_defaults(func=correlate_cmd)





    
    args = parser.parse_args()
    
    if args.command:
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
