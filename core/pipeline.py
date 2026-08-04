import os
import shutil
import json
from datetime import datetime
from core.scanner import DocumentScanner
from core.deobfuscator import MacroDeobfuscator
from core.quarantine_manager import QuarantineManager

# ---------------------------------------------------------------------------
# Pipeline constants
# ---------------------------------------------------------------------------

RISK_THRESHOLD            = 50  # Cumulative score at or above this → BLOCKED
WEIGHT_BASE64_PAYLOAD     = 40  # Weight added when a decoded base64 payload is found
DECODED_PAYLOAD_PREVIEW_LEN = 80  # Max characters of a decoded payload shown in finding desc


class GatekeeperPipeline:
    def __init__(self, file_path: str):
        """
        Initialises the pipeline for a single document scan.

        Resolves the file path to an absolute path, initialises all component
        classes (scanner, quarantine manager), and sets up the audit log path
        relative to this file's location so it works regardless of the working
        directory the CLI is invoked from.

        Args:
            file_path: Path to the workbook to scan (absolute or relative).
        """
        self.file_path = os.path.abspath(file_path)
        self.filename = os.path.basename(file_path)
        self.scanner = DocumentScanner(self.file_path)
        self.quarantine_manager = QuarantineManager()

        base_dir = os.path.dirname(os.path.abspath(__file__))
        logs_dir = os.path.join(base_dir, "..", "logs")
        os.makedirs(logs_dir, exist_ok=True)
        self.audit_log_path = os.path.join(logs_dir, "audit_log.jsonl")

    def _log_audit(self, verdict: str, risk_score: int, findings: list, destination: str):
        """
        Appends a single scan record to logs/audit_log.jsonl.

        Uses JSON Lines (JSONL) format — each entry is a self-contained JSON
        object on one line. A mid-write crash corrupts at most the current
        line; all previous entries remain valid and parseable. The log is
        append-only and never modified after writing.

        Args:
            verdict:     "CLEAN" or "BLOCKED".
            risk_score:  Final cumulative risk score for this scan.
            findings:    List of finding dicts produced by the scanner.
            destination: Path where the file was routed after scanning.
        """
        log_entry = {
            "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename":       self.filename,
            "file_path":      self.file_path,
            "verdict":        verdict,
            "risk_score":     risk_score,
            "destination":    destination,
            "findings_count": len(findings),
            "findings":       findings
        }

        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"[!] Error writing to audit log: {e}")

    def run(self) -> dict:
        """
        Executes the complete Gatekeeper pipeline for the initialised file.

        Steps:
            1. Static analysis — calls DocumentScanner.analyze() which runs
               all six layers (VBA, deobfuscation, XLM, custom rules,
               YARA, co-occurrence heuristic).
            2. Second-pass deobfuscation — runs MacroDeobfuscator again on
               the full extracted corpus to catch any base64 payloads not
               surfaced during the scanner's internal deobfuscation pass.
               Discovered payloads are folded back into the risk score.
            3. Verdict and routing — files scoring >= RISK_THRESHOLD are
               BLOCKED and copied to quarantine/. Files below threshold are
               CLEAN and copied to clean_output/ with macros intact.
            4. Audit logging — appends the full scan record to
               logs/audit_log.jsonl.

        Returns:
            dict with keys:
                risk_score (int)   — final cumulative score
                verdict (str)      — "CLEAN" or "BLOCKED"
                destination (str)  — path the file was routed to
                findings (list)    — all findings from all layers
        """
        # Step 1: Static analysis across all six layers
        scan_results = self.scanner.analyze()
        risk_score = scan_results["risk_score"]
        findings = scan_results["findings"]
        extracted_code = scan_results.get("extracted_code", "")

        # Step 2: Second-pass deobfuscation on the full corpus
        deobfuscator = MacroDeobfuscator([extracted_code] if extracted_code else [])
        deobfuscated_results = deobfuscator.clean_strings()

        for res in deobfuscated_results:
            for b64 in res.get("base64_artifacts", []):
                decoded_payload = b64.get("decoded", "")
                if decoded_payload:
                    finding_entry = {
                        "rule": "Deobfuscated_Base64_Payload",
                        "weight": WEIGHT_BASE64_PAYLOAD,
                        "desc": (
                            f"Decoded base64 payload reveals hidden string: "
                            f"{decoded_payload[:DECODED_PAYLOAD_PREVIEW_LEN]}"
                        )
                    }
                    if finding_entry not in findings:
                        findings.append(finding_entry)
                        risk_score += WEIGHT_BASE64_PAYLOAD

        # Step 3: Verdict and routing
        if risk_score >= RISK_THRESHOLD:
            verdict = "BLOCKED"
            destination = self.quarantine_manager.quarantine_file(self.file_path)
        else:
            verdict = "CLEAN"
            os.makedirs("clean_output", exist_ok=True)
            base_name, ext = os.path.splitext(self.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            target_filename = f"{base_name}_{timestamp}{ext}"
            destination = os.path.join("clean_output", target_filename)
            shutil.copy(self.file_path, destination)

        # Step 4: Audit log
        self._log_audit(verdict, risk_score, findings, destination)

        return {
            "risk_score":  risk_score,
            "verdict":     verdict,
            "destination": destination,
            "findings":    findings
        }

    def execute(self) -> dict:
        """
        Public alias for run(). Allows external callers to use a consistent
        verb without depending on the internal method name.

        Returns:
            The same dict returned by run().
        """
        return self.run()
