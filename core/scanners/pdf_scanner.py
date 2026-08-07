import os
import re

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ---------------------------------------------------------------------------
# PDF scanner risk weight constants
# ---------------------------------------------------------------------------

WEIGHT_JS_DETECTED          = 50  # JavaScript embedded in PDF — high risk
WEIGHT_LAUNCH_ACTION        = 60  # /Launch action — executes external program
WEIGHT_OPENACTION           = 30  # /OpenAction — runs on document open
WEIGHT_EMBEDDED_FILE        = 40  # Embedded file object inside PDF
WEIGHT_AUTO_ACTION          = 35  # /AA (Additional Actions) trigger
WEIGHT_URI_ACTION           = 20  # External URI action
WEIGHT_SUSPICIOUS_KEYWORD   = 30  # Known malicious PDF keywords
WEIGHT_ENCRYPT_SUSPICIOUS   = 25  # Encryption with suspicious permissions
WEIGHT_FORM_ACTION          = 20  # Form submit action (data exfiltration risk)
WEIGHT_RICH_MEDIA           = 25  # Rich media annotation (Flash/video embed)

PDF_THRESHOLD = 60  # Higher than macro threshold — PDF FP rate is higher

# Keywords in PDF stream content that indicate malicious activity
SUSPICIOUS_PDF_KEYWORDS = [
    "/JavaScript", "/JS",           # JavaScript execution
    "/Launch",                       # Launches external application
    "/OpenAction",                   # Auto-executes on open
    "/AA",                           # Additional Actions
    "/EmbeddedFile",                 # File embedded inside PDF
    "/RichMedia",                    # Rich media (Flash)
    "/XFA",                          # XML Forms Architecture (exploit vector)
    "/AcroForm",                     # Acrobat form with potential actions
    "eval(",                         # JS eval — classic obfuscation
    "unescape(",                     # JS unescape — shellcode staging
    "String.fromCharCode",           # JS char-by-char construction
    "/JBIG2Decode",                  # CVE-2009-0658 exploit filter
    "/ASCIIHexDecode",               # Obfuscation filter chain
    "/FlateDecode",                  # Compressed stream (normal but noted)
    "app.alert",                     # JS alert — social engineering
    "this.exportDataObject",         # JS file export
    "util.printf",                   # CVE-2008-2992 exploit
    "Collab.collectEmailInfo",       # CVE-2007-0106 exploit
]


class PDFScanner:
    def __init__(self, file_path: str):
        """
        Initialises the PDF scanner for a single document.

        Args:
            file_path: Absolute path to the PDF file to analyse.
        """
        self.file_path = os.path.abspath(file_path)
        self.findings  = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs deep static analysis of a PDF file.

        Analysis covers:
            1. Raw stream keyword scanning — JavaScript, Launch, OpenAction,
               EmbeddedFile, RichMedia, XFA, known exploit filter chains
            2. Structural analysis via pypdf — page actions, embedded files,
               encryption flags, form actions, URI actions
            3. Suspicious URL extraction from stream content

        PDF threshold is higher (60) than macro threshold (50) because
        PDF false-positive rates are higher — many legitimate PDFs use
        features like forms and encryption.

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_text = ""

        # ----------------------------------------------------------------
        # Layer 1: Raw stream keyword scanning
        # Read the raw bytes and scan for known malicious PDF keywords.
        # This catches obfuscated content that pypdf's parser may not expose.
        # ----------------------------------------------------------------
        try:
            with open(self.file_path, "rb") as f:
                raw_content = f.read().decode("latin-1", errors="ignore")

            extracted_text = raw_content

            for keyword in SUSPICIOUS_PDF_KEYWORDS:
                if keyword.lower() in raw_content.lower():
                    if keyword in {"/JavaScript", "/JS"}:
                        weight = WEIGHT_JS_DETECTED
                        desc   = "JavaScript detected in PDF — primary exploit delivery vector."
                    elif keyword == "/Launch":
                        weight = WEIGHT_LAUNCH_ACTION
                        desc   = "/Launch action detected — executes an external program on open."
                    elif keyword == "/OpenAction":
                        weight = WEIGHT_OPENACTION
                        desc   = "/OpenAction detected — PDF executes an action automatically on open."
                    elif keyword == "/EmbeddedFile":
                        weight = WEIGHT_EMBEDDED_FILE
                        desc   = "Embedded file object found — PDF contains a hidden attachment."
                    elif keyword == "/AA":
                        weight = WEIGHT_AUTO_ACTION
                        desc   = "/AA (Additional Actions) detected — triggers on page events."
                    elif keyword == "/RichMedia":
                        weight = WEIGHT_RICH_MEDIA
                        desc   = "Rich media annotation detected — embedded Flash or video content."
                    elif keyword in {"eval(", "unescape(", "String.fromCharCode"}:
                        weight = WEIGHT_JS_DETECTED
                        desc   = f"JavaScript obfuscation pattern '{keyword}' found in PDF stream."
                    elif keyword in {"/JBIG2Decode", "util.printf", "Collab.collectEmailInfo"}:
                        weight = WEIGHT_SUSPICIOUS_KEYWORD
                        desc   = f"Known exploit indicator '{keyword}' found in PDF content."
                    else:
                        weight = WEIGHT_SUSPICIOUS_KEYWORD
                        desc   = f"Suspicious PDF keyword '{keyword}' detected in document stream."

                    finding = {
                        "rule":   f"PDF_{keyword.strip('/').replace('.', '_')}",
                        "weight": weight,
                        "desc":   desc
                    }
                    if finding not in self.findings:
                        self.findings.append(finding)
                        self.risk_score += weight

        except Exception as e:
            self.findings.append({
                "rule":   "PDF_ReadError",
                "weight": 20,
                "desc":   f"Could not read raw PDF content: {e}"
            })

        # ----------------------------------------------------------------
        # Layer 2: Structural analysis via pypdf
        # ----------------------------------------------------------------
        if PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(self.file_path)

                # Check document-level open action
                if "/OpenAction" in reader.trailer_id:
                    self._add_unique({
                        "rule":   "PDF_OpenAction_Structural",
                        "weight": WEIGHT_OPENACTION,
                        "desc":   "PDF structural analysis confirms /OpenAction at document level."
                    })

                # Check encryption
                if reader.is_encrypted:
                    self.findings.append({
                        "rule":   "PDF_Encrypted",
                        "weight": WEIGHT_ENCRYPT_SUSPICIOUS,
                        "desc":   "PDF is encrypted — may conceal malicious content from scanners."
                    })
                    self.risk_score += WEIGHT_ENCRYPT_SUSPICIOUS

                # Scan each page for annotations and actions
                for page_num, page in enumerate(reader.pages):
                    page_obj = page.get_object()

                    # Page-level Additional Actions
                    if "/AA" in page_obj:
                        self._add_unique({
                            "rule":   "PDF_Page_AdditionalAction",
                            "weight": WEIGHT_AUTO_ACTION,
                            "desc":   f"Page {page_num+1} has Additional Actions (/AA) — triggers on page events."
                        })

                    # Annotations with actions
                    if "/Annots" in page_obj:
                        annots = page_obj["/Annots"]
                        for annot in annots:
                            try:
                                annot_obj = annot.get_object()
                                if "/A" in annot_obj:
                                    action = annot_obj["/A"]
                                    if hasattr(action, "get_object"):
                                        action = action.get_object()
                                    action_type = action.get("/S", "")
                                    if action_type == "/URI":
                                        uri = action.get("/URI", "")
                                        self._add_unique({
                                            "rule":   "PDF_URI_Action",
                                            "weight": WEIGHT_URI_ACTION,
                                            "desc":   f"URI action found: {str(uri)[:100]}"
                                        })
                                    elif action_type == "/Launch":
                                        self._add_unique({
                                            "rule":   "PDF_Launch_Action_Annot",
                                            "weight": WEIGHT_LAUNCH_ACTION,
                                            "desc":   "Launch action in annotation — executes external program."
                                        })
                                    elif action_type == "/SubmitForm":
                                        self._add_unique({
                                            "rule":   "PDF_Form_Submit",
                                            "weight": WEIGHT_FORM_ACTION,
                                            "desc":   "Form submit action — may exfiltrate data to external server."
                                        })
                            except Exception:
                                continue

            except Exception as e:
                self.findings.append({
                    "rule":   "PDF_ParseError",
                    "weight": 0,
                    "desc":   f"pypdf structural analysis error (non-fatal): {e}"
                })
        else:
            self.findings.append({
                "rule":   "PDF_pypdf_Unavailable",
                "weight": 0,
                "desc":   "pypdf not installed. Install with: pip install pypdf"
            })

        # ----------------------------------------------------------------
        # Layer 3: Suspicious URL extraction
        # ----------------------------------------------------------------
        urls = re.findall(r'https?://[^\s\'">\]){]+', extracted_text)
        suspicious_tlds = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club"}
        for url in set(urls):
            if any(tld in url.lower() for tld in suspicious_tlds):
                self._add_unique({
                    "rule":   "PDF_Suspicious_URL",
                    "weight": 25,
                    "desc":   f"Suspicious URL with high-risk TLD found: {url[:100]}"
                })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text[:500],
            "threshold":      PDF_THRESHOLD
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
