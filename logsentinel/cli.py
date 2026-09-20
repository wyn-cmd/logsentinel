import sys
import argparse
import json
from logsentinel.scanner import LogScanner

def main():
    parser = argparse.ArgumentParser(description="LogSentinel local log anomaly scanner & threat triage.")
    subparsers = parser.add_subparsers(dest="command")
    
    scan_parser = subparsers.add_parser("scan", help="Scan a log file for anomalies and risk score")
    scan_parser.add_argument("path", help="Path to the log file")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        scanner = LogScanner(args.path)
        res = scanner.scan()
        if "error" in res:
            print(f"Error reading file: {res['error']}")
            sys.exit(1)
            
        if args.json:
            print(json.dumps(res, indent=2))
            return
            
        print(f"Scanned {res['total_lines']} lines in {args.path}")
        print(f"Authentication failures: {res['failed_password_count']}")
        print(f"Privilege events / sudo: {res['sudo_anomaly_count']}")
        print(f"Error indicators: {res['error_count']}")
        print(f"Calculated Risk Score: {res['risk_score']}")
        print("-" * 45)
        
        for item in res['anomalies'][:50]:
            print(f"[{item['line']}] [{item['type']}] {item['content']}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
