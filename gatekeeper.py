import argparse
from core.pipeline import GatekeeperPipeline
from core.quarantine_manager import QuarantineManager


def main():
    """
    Entry point for the Gatekeeper CLI.

    Parses command-line arguments and dispatches to one of two modes:

        File scan (default):
            python gatekeeper.py <file>
            Runs the full pipeline against the given workbook. Files scoring
            >= RISK_THRESHOLD are BLOCKED and quarantined. Files below
            threshold are CLEAN and forwarded to clean_output/ with macros intact.

        Triage (--triage):
            python gatekeeper.py --triage
            Lists all quarantined files with SHA-256 hashes, risk scores,
            findings counts, and scan timestamps from the audit log.
    """
    parser = argparse.ArgumentParser(
        description="Gatekeeper Office Document Security Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the document to scan"
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="List all quarantined files with hashes, scores, and scan details"
    )

    args = parser.parse_args()
    manager = QuarantineManager()

    # ------------------------------------------------------------------
    # Mode: --triage
    # ------------------------------------------------------------------
    if args.triage:
        print("[*] Running Quarantine Triage Analysis...")
        reports = manager.triage_quarantine()

        if not reports:
            print("[+] Quarantine folder is currently empty.")
            return

        print(f"[+] Found {len(reports)} quarantined item(s):\n")
        for report in reports:
            print(f"    {'─' * 60}")
            print(f"    Filename     : {report['filename']}")
            print(f"    SHA-256      : {report['sha256_hash']}")
            print(f"    Size         : {report['size_bytes']} bytes")
            print(f"    Risk Score   : {report['risk_score']}")
            print(f"    Findings     : {report['findings_count']}")
            print(f"    Scanned At   : {report['scanned_at']}")
            print(f"    Status       : {report['status']}")
        print(f"    {'─' * 60}")
        return

    # ------------------------------------------------------------------
    # Mode: file scan (default)
    # ------------------------------------------------------------------
    if not args.file:
        parser.print_help()
        return

    print(f"[*] Initializing Gatekeeper Pipeline for: {args.file}")
    pipeline = GatekeeperPipeline(args.file)
    result = pipeline.execute()

    print(f"[+] Scan Complete.")
    print(f"    - Verdict        : {result['verdict']}")
    print(f"    - Risk Score     : {result['risk_score']}")
    print(f"    - Destination    : {result['destination']}")
    print(f"    - Findings Count : {len(result['findings'])}")


if __name__ == "__main__":
    main()