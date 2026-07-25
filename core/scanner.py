import os
import json
from oletools.olevba import VBA_Parser
from core.deobfuscator import MacroDeobfuscator

try:
    from XLMMacroDeobfuscator.deobfuscator import process_file
    XLM_AVAILABLE = True
except ImportError:
    XLM_AVAILABLE = False

class DocumentScanner:
    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self.findings = []
        self.risk_score = 0
        self.ignored_keywords = {"Hex Strings", "Base64 Strings", "vbNormalFocus"}
        self.custom_rules = self._load_custom_rules()

    def _load_custom_rules(self):
        rule_path = os.path.join("rules", "macro_rules.json")
        if os.path.exists(rule_path):
            try:
                with open(rule_path, "r") as f:
                    data = json.load(f)
                    return data.get("rules", [])
            except Exception:
                return []
        return []

    def analyze(self):
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_code_corpus = ""

        # 1. VBA Macro Scanning via olevba
        vba_parser = VBA_Parser(self.file_path)
        try:
            if vba_parser.detect_vba_macros():
                self.findings.append({
                    "rule": "VBA_Macros_Detected",
                    "weight": 0,
                    "desc": "The document contains embedded VBA macros."
                })

                for filename, stream_path, vba_filename, vba_code in vba_parser.extract_all_macros():
                    if vba_code:
                        extracted_code_corpus += vba_code + "\n"

                    results = vba_parser.analyze_macros()
                    for kw_type, keyword, description in results:
                        if keyword in self.ignored_keywords or kw_type in self.ignored_keywords:
                            continue

                        if kw_type in {"AutoExec", "IOC"} or keyword.lower() in {"shell", "createobject", "environ", "exec"}:
                            weight = 30
                        else:
                            weight = 10

                        finding_entry = {
                            "rule": f"SuspiciousKeyword_{kw_type}",
                            "weight": weight,
                            "desc": f"Found {kw_type} keyword '{keyword}': {description}"
                        }
                        if finding_entry not in self.findings:
                            self.findings.append(finding_entry)
                            self.risk_score += weight
            else:
                self.findings.append({
                    "rule": "No_VBA_Macros",
                    "weight": 0,
                    "desc": "No active VBA macros were detected in the document."
                })
        except Exception as e:
            self.findings.append({
                "rule": "ScanError",
                "weight": 40,
                "desc": f"Error parsing document macros: {str(e)}"
            })
            self.risk_score += 40
        finally:
            vba_parser.close()

        # 2. String Deobfuscation & Normalization Feedback Loop
        # Run deobfuscator immediately after code extraction so findings feed into rules & heuristics
        if extracted_code_corpus:
            deobfuscator = MacroDeobfuscator(extracted_code_corpus)
            deobfuscated_output = deobfuscator.clean_strings()
            
            # If the deobfuscator extracted decoded strings / payloads, append them to the corpus
            if deobfuscated_output:
                extracted_code_corpus += "\n" + str(deobfuscated_output)
                self.findings.append({
                    "rule": "Deobfuscation_Payload_Extracted",
                    "weight": 20,
                    "desc": "Successfully reconstructed obfuscated or encoded string payloads."
                })
                self.risk_score += 20

        # 3. Excel 4.0 / XLM Macro Scanning
        if XLM_AVAILABLE:
            try:
                xlm_results = process_file(file=self.file_path, noninteractive=True)
                if xlm_results:
                    self.findings.append({
                        "rule": "XLM_Macros_Detected",
                        "weight": 30,
                        "desc": "Legacy Excel 4.0 (XLM) macro sheets or formulas detected."
                    })
                    self.risk_score += 30
            except Exception:
                pass

        # 4. Custom Rule Pattern Matching (Evaluates normalized/deobfuscated corpus)
        for rule in self.custom_rules:
            rule_name = rule.get("name")
            weight = rule.get("weight", 30)
            patterns = rule.get("patterns", [])
            desc = rule.get("description", "")

            matched = False
            for pattern in patterns:
                if pattern.lower() in extracted_code_corpus.lower():
                    matched = True
                    break

            if matched:
                self.findings.append({
                    "rule": f"Rule_{rule_name}",
                    "weight": weight,
                    "desc": desc
                })
                self.risk_score += weight

        # 5. Keyword Co-occurrence Heuristic (Evaluates normalized/deobfuscated corpus)
        if extracted_code_corpus:
            behavioral_triggers = ["shell", "createobject", "wscript.shell", "environ", "exec", "powershell"]
            triggered_behaviors = [trig for trig in behavioral_triggers if trig in extracted_code_corpus.lower()]
            
            if len(triggered_behaviors) >= 2:
                self.findings.append({
                    "rule": "Keyword_Cooccurrence_Heuristic",
                    "weight": 40,
                    "desc": f"Keyword co-occurrence heuristic detected chained risk indicators: {', '.join(triggered_behaviors)}"
                })
                self.risk_score += 40

        return {
            "risk_score": self.risk_score,
            "findings": self.findings,
            "extracted_code": extracted_code_corpus
        }