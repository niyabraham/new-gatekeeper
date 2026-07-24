import argparse
from core.pipeline import GatekeeperPipeline
from core.quarantine_manager import QuarantineManager

def main():
    parser = argparse.ArgumentParser(description="Gatekeeper Office Document Security Scanner")
    parser.add_argument("file", nargs="?", help="Path to the document to scan")
    parser.add_argument("--triage", action="store_true", help="Scan and generate hashes for quarantined files")
    args = parser.parse_args()

    if args.triage:
        print("[*] Running Quarantine Triage Analysis...")
        manager = QuarantineManager()
        reports = manager.triage_quarantine()
        
        if not reports:
            print("[+] Quarantine folder is currently empty.")
        else:
            print(f"[+] Found {len(reports)} quarantined item(s):")
            for report in reports:
                print(f"    ----------------------------------------")
                print(f"    - Filename : {report['filename']}")
                print(f"    - SHA-256  : {report['sha256_hash']}")
                print(f"    - Size     : {report['size_bytes']} bytes")
                print(f"    - Status   : {report['status']}")
            print(f"    ----------------------------------------")
        return

    # Handle standard document scan
    if not args.file:
        parser.print_help()
        return

    print(f"[*] Initializing Gatekeeper Pipeline for: {args.file}")
    pipeline = GatekeeperPipeline(args.file)
    result = pipeline.execute()
    
    print(f"[+] Scan Complete.")
    print(f"    - Verdict: {result['verdict']}")
    print(f"    - Risk Score: {result['risk_score']}")
    print(f"    - Destination: {result['destination']}")
    print(f"    - Findings Count: {len(result['findings'])}")

if __name__ == "__main__":
    main()