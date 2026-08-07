import os
import re
import zipfile
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Office scanner risk weight constants
# (.docx and .xlsx — Open XML formats without VBA macros)
# ---------------------------------------------------------------------------

WEIGHT_EXTERNAL_RELATIONSHIP = 40  # Relationship pointing to external resource
WEIGHT_EMBEDDED_OBJECT       = 45  # OLE object embedded in document
WEIGHT_SUSPICIOUS_URL        = 30  # Suspicious URL in document content
WEIGHT_MACRO_REF             = 50  # Reference to macros despite being non-macro format
WEIGHT_DDE_ATTACK            = 65  # Dynamic Data Exchange — command execution vector
WEIGHT_TEMPLATE_INJECTION    = 55  # Remote template injection via relationship
WEIGHT_SUSPICIOUS_FIELD      = 35  # Suspicious field codes (DDEAUTO, INCLUDE, etc.)
WEIGHT_HIDDEN_CONTENT        = 25  # Hidden text or rows with suspicious content
WEIGHT_SUSPICIOUS_CONTENT    = 20  # General suspicious keyword in content

OFFICE_THRESHOLD = 55  # Between macro (50) and image (65) — moderate risk format

# Namespaces used in OOXML documents
NS = {
    "r":   "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "w":   "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "x":   "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "mc":  "http://schemas.openxmlformats.org/markup-compatibility/2006",
}

# Field codes that enable command execution in Office documents
DANGEROUS_FIELD_CODES = [
    "DDEAUTO", "DDE",       # Dynamic Data Exchange — executes shell commands
    "INCLUDE",              # File inclusion
    "INCLUDEPICTURE",       # External resource load
    "INCLUDETEXT",          # External text inclusion
    "LINK",                 # OLE link
    "AUTOTEXT",             # Auto-inserted content
]

# Relationship types that indicate external or dangerous connections
DANGEROUS_REL_TYPES = [
    "attachedTemplate",     # Remote template injection
    "externalLink",         # External workbook link
    "oleObject",            # OLE embedded object
    "frame",                # HTML frame
    "hyperlink",            # External hyperlink (scored lower)
]

SUSPICIOUS_CONTENT_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", "wget", "curl", "invoke-expression",
    "downloadstring", "downloadfile",
]


class OfficeScanner:
    def __init__(self, file_path: str):
        """
        Initialises the Office scanner for a .docx or .xlsx file.

        These formats are OOXML containers (ZIP archives) without VBA macros.
        Analysis focuses on relationship abuse, DDE attacks, embedded objects,
        and remote template injection rather than macro code.

        Args:
            file_path: Absolute path to the .docx or .xlsx file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs deep static analysis of a .docx or .xlsx file.

        Analysis covers:
            1. Relationship scanning — checks all .rels files for external
               links, remote templates, OLE objects, and frame references
            2. Field code scanning — detects DDE, DDEAUTO, and other
               dangerous field codes that execute commands
            3. Content scanning — searches document XML for suspicious
               keywords and shell command patterns
            4. Embedded object detection — identifies OLE objects and
               external data connections

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        if not zipfile.is_zipfile(self.file_path):
            self.findings.append({
                "rule":   "Office_InvalidFormat",
                "weight": 20,
                "desc":   "File does not appear to be a valid OOXML container."
            })
            self.risk_score += 20
            return {
                "risk_score": self.risk_score,
                "findings":   self.findings,
                "extracted_code": "",
                "threshold":  OFFICE_THRESHOLD
            }

        extracted_text = ""

        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                all_files = zf.namelist()

                # ----------------------------------------------------------------
                # Layer 1: Relationship file scanning
                # ----------------------------------------------------------------
                rel_files = [f for f in all_files if f.endswith(".rels")]
                for rel_file in rel_files:
                    try:
                        rel_content = zf.read(rel_file).decode("utf-8", errors="ignore")
                        extracted_text += rel_content + "\n"

                        root = ET.fromstring(rel_content)
                        for rel in root.findall(".//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                            rel_type   = rel.get("Type", "")
                            target     = rel.get("Target", "")
                            target_mode = rel.get("TargetMode", "Internal")

                            rel_type_short = rel_type.split("/")[-1]

                            # External relationship pointing outside document
                            if target_mode == "External":
                                if "attachedTemplate" in rel_type:
                                    self._add_unique({
                                        "rule":   "Office_Remote_Template_Injection",
                                        "weight": WEIGHT_TEMPLATE_INJECTION,
                                        "desc":   f"Remote template injection: document loads template from '{target}'"
                                    })
                                elif "oleObject" in rel_type:
                                    self._add_unique({
                                        "rule":   "Office_External_OLE",
                                        "weight": WEIGHT_EMBEDDED_OBJECT,
                                        "desc":   f"External OLE object link: '{target}'"
                                    })
                                elif "externalLink" in rel_type:
                                    self._add_unique({
                                        "rule":   "Office_External_Link",
                                        "weight": WEIGHT_EXTERNAL_RELATIONSHIP,
                                        "desc":   f"External workbook/data link: '{target}'"
                                    })
                                elif target.startswith("http"):
                                    self._add_unique({
                                        "rule":   "Office_External_URL_Relationship",
                                        "weight": WEIGHT_SUSPICIOUS_URL,
                                        "desc":   f"External URL relationship: '{target[:100]}'"
                                    })

                            # OLE embedded object (internal)
                            if "oleObject" in rel_type and target_mode == "Internal":
                                self._add_unique({
                                    "rule":   "Office_Embedded_OLE_Object",
                                    "weight": WEIGHT_EMBEDDED_OBJECT,
                                    "desc":   f"Embedded OLE object found in document: '{target}'"
                                })

                    except Exception:
                        continue

                # ----------------------------------------------------------------
                # Layer 2: Document content scanning (field codes + keywords)
                # ----------------------------------------------------------------
                content_files = [
                    f for f in all_files
                    if f.endswith(".xml") and not f.endswith(".rels")
                ]

                for content_file in content_files:
                    try:
                        content = zf.read(content_file).decode("utf-8", errors="ignore")
                        extracted_text += content + "\n"

                        # DDE field code detection
                        for field_code in DANGEROUS_FIELD_CODES:
                            if field_code in content.upper():
                                weight = WEIGHT_DDE_ATTACK if "DDE" in field_code else WEIGHT_SUSPICIOUS_FIELD
                                self._add_unique({
                                    "rule":   f"Office_Field_{field_code}",
                                    "weight": weight,
                                    "desc":   (
                                        f"Dangerous field code '{field_code}' found in {content_file}. "
                                        f"DDE fields can execute arbitrary shell commands."
                                        if "DDE" in field_code else
                                        f"Suspicious field code '{field_code}' found in {content_file}."
                                    )
                                })

                        # Shell command keyword detection in content
                        content_lower = content.lower()
                        for keyword in SUSPICIOUS_CONTENT_KEYWORDS:
                            if keyword in content_lower:
                                self._add_unique({
                                    "rule":   f"Office_Content_{keyword.replace('.', '_').replace('-', '_')}",
                                    "weight": WEIGHT_SUSPICIOUS_CONTENT,
                                    "desc":   f"Shell command keyword '{keyword}' found in document content."
                                })

                        # Suspicious URL detection
                        urls = re.findall(r'https?://[^\s\'"<>&]+', content)
                        suspicious_tlds = {".ru", ".cn", ".tk", ".pw", ".xyz", ".top"}
                        for url in set(urls):
                            if any(tld in url.lower() for tld in suspicious_tlds):
                                self._add_unique({
                                    "rule":   "Office_Suspicious_URL",
                                    "weight": WEIGHT_SUSPICIOUS_URL,
                                    "desc":   f"Suspicious URL with high-risk TLD: {url[:100]}"
                                })

                    except Exception:
                        continue

                # ----------------------------------------------------------------
                # Layer 3: Check for unexpected macro-related files
                # .docx/.xlsx should not contain vbaProject.bin
                # ----------------------------------------------------------------
                if "xl/vbaProject.bin" in all_files or "word/vbaProject.bin" in all_files:
                    self._add_unique({
                        "rule":   "Office_Unexpected_VBA",
                        "weight": WEIGHT_MACRO_REF,
                        "desc":   "vbaProject.bin found in non-macro format — file may be mislabelled .xlsm/.docm."
                    })

        except zipfile.BadZipFile:
            self.findings.append({
                "rule":   "Office_CorruptZip",
                "weight": 20,
                "desc":   "File appears corrupt or is not a valid ZIP/OOXML container."
            })
            self.risk_score += 20

        except Exception as e:
            self.findings.append({
                "rule":   "Office_ScanError",
                "weight": 20,
                "desc":   f"Office scan error: {e}"
            })
            self.risk_score += 20

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text[:500],
            "threshold":      OFFICE_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        """
        Adds a finding only if it has not already been recorded,
        and accumulates its weight into the risk score.

        Args:
            finding: Finding dict with keys rule, weight, desc.
        """
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
