import os
import shutil
import json
from datetime import datetime
from core.scanner import DocumentScanner
from core.deobfuscator import MacroDeobfuscator
from core.quarantine_manager import QuarantineManager

class GatekeeperPipeline:
    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self.filename = os.path.basename(file_path)
        self.scanner = DocumentScanner(self.file_path)
        self.quarantine_manager = QuarantineManager()
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        logs_dir = os.path.join(base_dir, "..", "logs")
        os.makedirs(logs_dir, exist_ok=True)
        self.audit_log_path = os.path.join(logs_dir, "audit_log.jsonl")

    def _log_audit(self, verdict: str, risk_score: int, findings: list, destination: str):
        """Appends scan results to logs/audit_log.jsonl using crash-safe JSON Lines format."""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": self.filename,
            "file_path": self.file_path,
            "verdict": verdict,
            "risk_score": risk_score,
            "destination": destination,
            "findings_count": len(findings),
            "findings": findings
        }
        
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"[!] Error writing to audit log: {e}")

    def run(self):
        # 1. Static Analysis & Code Extraction
        scan_results = self.scanner.analyze()
        risk_score = scan_results["risk_score"]
        findings = scan_results["findings"]
        extracted_code = scan_results.get("extracted_code", "")

        # 2. Deobfuscation checks against actual macro code corpus
        deobfuscator = MacroDeobfuscator([extracted_code] if extracted_code else [])
        deobfuscated_results = deobfuscator.clean_strings()

        # Fold deobfuscation discoveries back into risk scoring
        for res in deobfuscated_results:
            for b64 in res.get("base64_artifacts", []):
                decoded_payload = b64.get("decoded", "")
                if decoded_payload:
                    finding_entry = {
                        "rule": "Deobfuscated_Base64_Payload",
                        "weight": 40,
                        "desc": f"Decoded base64 payload reveals hidden string: {decoded_payload[:80]}"
                    }
                    if finding_entry not in findings:
                        findings.append(finding_entry)
                        risk_score += 40

        # 3. Determine Verdict & Routing
        if risk_score >= 50:
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

        # 4. Record to Audit Log JSONL
        self._log_audit(verdict, risk_score, findings, destination)

        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "destination": destination,
            "findings": findings
        }

    def execute(self):
        return self.run()