import argparse
from core.pipeline import GatekeeperPipeline
from core.quarantine_manager import QuarantineManager


def main():
    """
    Entry point for the Gatekeeper CLI.

    Parses command-line arguments and dispatches to one of four modes:

        File scan (default):
            python gatekeeper.py <file>
            Runs the full pipeline against the given workbook. Files scoring
            >= RISK_THRESHOLD are BLOCKED and quarantined. Files below
            threshold are CLEAN and forwarded to clean_output/ with macros intact.

        Triage (--triage):
            python gatekeeper.py --triage
            Lists all quarantined files with SHA-256 hashes, risk scores,
            findings counts, and current analyst decision status.

        Confirm threat (--confirm):
            python gatekeeper.py --confirm <filename> --analyst <name> [--notes <text>]
            Marks a quarantined file as a confirmed threat. Requires --analyst.
            Decision is recorded in logs/analyst_decisions.jsonl.

        Release false positive (--release):
            python gatekeeper.py --release <filename> --analyst <name> [--reason <text>]
            Moves an analyst-verified safe file from quarantine to clean_output/.
            Requires --analyst. Decision is recorded in logs/analyst_decisions.jsonl.
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
        help="List all quarantined files with hashes, scores, and analyst status"
    )
    parser.add_argument(
        "--confirm",
        metavar="FILENAME",
        help="Mark a quarantined file as a confirmed threat (basename only)"
    )
    parser.add_argument(
        "--release",
        metavar="FILENAME",
        help="Release a false-positive file from quarantine back to clean_output/"
    )
    parser.add_argument(
        "--analyst",
        metavar="NAME",
        default="",
        help="Analyst name or ID (required with --confirm and --release)"
    )
    parser.add_argument(
        "--notes",
        metavar="TEXT",
        default="",
        help="Notes for --confirm (malware family, IOC details, etc.)"
    )
    parser.add_argument(
        "--reason",
        metavar="TEXT",
        default="",
        help="Justification for --release decision"
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
            if report['analyst']:
                print(f"    Analyst      : {report['analyst']}")
            if report['decided_at']:
                print(f"    Decided At   : {report['decided_at']}")
        print(f"    {'─' * 60}")
        return

    # ------------------------------------------------------------------
    # Mode: --confirm
    # ------------------------------------------------------------------
    if args.confirm:
        if not args.analyst:
            print("[!] --analyst NAME is required with --confirm.")
            return

        print(f"[*] Confirming threat: {args.confirm}")
        result = manager.confirm_threat(
            filename=args.confirm,
            analyst=args.analyst,
            notes=args.notes
        )

        if result["success"]:
            print(f"[+] Threat confirmed.")
            print(f"    - File    : {result['filename']}")
            print(f"    - Analyst : {result['analyst']}")
            print(f"    - Notes   : {result['notes'] or '(none)'}")
            print(f"    - Logged  : logs/analyst_decisions.jsonl")
        else:
            print(f"[!] Error: {result['error']}")
        return

    # ------------------------------------------------------------------
    # Mode: --release
    # ------------------------------------------------------------------
    if args.release:
        if not args.analyst:
            print("[!] --analyst NAME is required with --release.")
            return

        print(f"[*] Releasing file from quarantine: {args.release}")
        result = manager.release_file(
            filename=args.release,
            analyst=args.analyst,
            reason=args.reason
        )

        if result["success"]:
            print(f"[+] File released to clean_output/.")
            print(f"    - File        : {result['filename']}")
            print(f"    - Destination : {result['destination']}")
            print(f"    - Analyst     : {result['analyst']}")
            print(f"    - Reason      : {result['reason'] or '(none)'}")
            print(f"    - Logged      : logs/analyst_decisions.jsonl")
        else:
            print(f"[!] Error: {result['error']}")
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
