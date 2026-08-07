import os
import re
import struct

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# ---------------------------------------------------------------------------
# Image scanner risk weight constants
# ---------------------------------------------------------------------------

WEIGHT_EXIF_SCRIPT          = 50  # Script content in EXIF field
WEIGHT_SUSPICIOUS_COMMENT   = 40  # Malicious content in image comment field
WEIGHT_POLYGLOT_INDICATOR   = 60  # File is valid both as image and another format
WEIGHT_EMBEDDED_PE          = 70  # PE (Windows executable) header found in image
WEIGHT_SUSPICIOUS_URL       = 30  # Suspicious URL embedded in metadata
WEIGHT_ABNORMAL_SIZE        = 20  # File size disproportionate to image dimensions
WEIGHT_HIDDEN_ZIP           = 60  # ZIP/PK header found appended to image
WEIGHT_SUSPICIOUS_EXIF      = 25  # Suspicious software/tool name in EXIF

IMAGE_THRESHOLD = 65  # High threshold — steganography FP rate is high

# EXIF field names that are commonly abused for payload hiding
SENSITIVE_EXIF_FIELDS = {
    "ImageDescription", "UserComment", "Artist",
    "Copyright", "Software", "Make", "Model",
    "XPComment", "XPKeywords", "XPSubject"
}

# Patterns that should never appear in legitimate image metadata
MALICIOUS_EXIF_PATTERNS = [
    r'<script',             # HTML/JS injection
    r'eval\s*\(',           # JS eval
    r'powershell',          # PowerShell command
    r'cmd\.exe',            # Windows shell
    r'base64',              # Base64 encoded payload
    r'http[s]?://',         # URL in metadata
    r'\\x[0-9a-fA-F]{2}',  # Hex-encoded bytes
    r'wget\s+',             # Download command
    r'curl\s+',             # Download command
]


class ImageScanner:
    def __init__(self, file_path: str):
        """
        Initialises the image scanner for a single image file.

        Args:
            file_path: Absolute path to the image file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs deep static analysis of an image file.

        Analysis covers:
            1. EXIF metadata scanning — checks all text fields for injected
               scripts, commands, URLs, and encoded payloads
            2. Magic byte / polyglot detection — checks if the file also
               contains valid headers for other formats (ZIP, PE, PDF)
            3. Appended data detection — checks for content after the
               legitimate image data (common steganography technique)
            4. File size anomaly detection — disproportionate size relative
               to image dimensions indicates hidden payload

        Image threshold is high (65) because steganography is relatively
        rare and false positive rate for this format is higher than macros.

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_notes = []

        # ----------------------------------------------------------------
        # Layer 1: EXIF metadata analysis
        # ----------------------------------------------------------------
        if PILLOW_AVAILABLE:
            try:
                img = Image.open(self.file_path)

                # Record basic image properties
                width, height = img.size
                extracted_notes.append(
                    f"Image: {width}x{height} {img.format} {img.mode}"
                )

                # Size anomaly check
                file_size  = os.path.getsize(self.file_path)
                pixel_count = width * height
                if pixel_count > 0:
                    bytes_per_pixel = file_size / pixel_count
                    if bytes_per_pixel > 10:
                        self._add_unique({
                            "rule":   "Image_Abnormal_Size",
                            "weight": WEIGHT_ABNORMAL_SIZE,
                            "desc":   (
                                f"File size ({file_size} bytes) is disproportionately large "
                                f"for image dimensions ({width}x{height}) — "
                                f"{bytes_per_pixel:.1f} bytes/pixel suggests hidden content."
                            )
                        })

                # EXIF extraction and scanning
                exif_data = img._getexif() if hasattr(img, "_getexif") else None
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = TAGS.get(tag_id, str(tag_id))
                        if not isinstance(value, (str, bytes)):
                            continue

                        str_value = value.decode("utf-8", errors="ignore") \
                            if isinstance(value, bytes) else str(value)

                        extracted_notes.append(f"EXIF {tag_name}: {str_value[:100]}")

                        # Scan sensitive fields for malicious patterns
                        if tag_name in SENSITIVE_EXIF_FIELDS:
                            for pattern in MALICIOUS_EXIF_PATTERNS:
                                if re.search(pattern, str_value, re.IGNORECASE):
                                    self._add_unique({
                                        "rule":   f"Image_EXIF_{tag_name}_Injection",
                                        "weight": WEIGHT_EXIF_SCRIPT,
                                        "desc":   (
                                            f"Malicious pattern '{pattern}' found in "
                                            f"EXIF field '{tag_name}': {str_value[:80]}"
                                        )
                                    })

                        # Check for suspicious software tools
                        if tag_name == "Software":
                            suspicious_tools = [
                                "steghide", "openstego", "stegano",
                                "outguess", "stegosuite", "jphide"
                            ]
                            if any(t in str_value.lower() for t in suspicious_tools):
                                self._add_unique({
                                    "rule":   "Image_Steganography_Tool",
                                    "weight": WEIGHT_SUSPICIOUS_EXIF,
                                    "desc":   f"Known steganography tool in EXIF Software field: {str_value[:80]}"
                                })

            except Exception as e:
                self.findings.append({
                    "rule":   "Image_EXIF_ParseError",
                    "weight": 0,
                    "desc":   f"EXIF parsing error (non-fatal): {e}"
                })
        else:
            self.findings.append({
                "rule":   "Image_Pillow_Unavailable",
                "weight": 0,
                "desc":   "Pillow not installed. Install with: pip install Pillow"
            })

        # ----------------------------------------------------------------
        # Layer 2: Magic byte / polyglot / appended data detection
        # Read raw bytes and check for embedded format signatures.
        # ----------------------------------------------------------------
        try:
            with open(self.file_path, "rb") as f:
                raw = f.read()

            # PE (Windows executable) header anywhere in file
            if b"MZ" in raw[100:] or b"\x4d\x5a\x90\x00" in raw:
                self._add_unique({
                    "rule":   "Image_Embedded_PE",
                    "weight": WEIGHT_EMBEDDED_PE,
                    "desc":   "Windows PE (executable) header found inside image file — polyglot or dropper."
                })

            # ZIP/PK header appended after image data
            if b"PK\x03\x04" in raw[100:]:
                self._add_unique({
                    "rule":   "Image_Appended_ZIP",
                    "weight": WEIGHT_HIDDEN_ZIP,
                    "desc":   "ZIP archive signature (PK header) found appended to image — hidden archive."
                })

            # PDF header embedded in image
            if b"%PDF" in raw[100:]:
                self._add_unique({
                    "rule":   "Image_Embedded_PDF",
                    "weight": WEIGHT_POLYGLOT_INDICATOR,
                    "desc":   "PDF header found inside image file — polyglot file indicator."
                })

            # PHP/script content in image (webshell delivery via image upload)
            script_patterns = [b"<?php", b"<script", b"eval(", b"base64_decode("]
            for pattern in script_patterns:
                if pattern in raw:
                    self._add_unique({
                        "rule":   "Image_Script_Injection",
                        "weight": WEIGHT_SUSPICIOUS_COMMENT,
                        "desc":   f"Script content '{pattern.decode()}' found in image binary data."
                    })

            # URLs in raw image data
            urls = re.findall(rb'https?://[^\s\'">\]){]+', raw)
            suspicious_tlds = [b".ru", b".cn", b".tk", b".pw", b".xyz"]
            for url in set(urls):
                if any(tld in url for tld in suspicious_tlds):
                    self._add_unique({
                        "rule":   "Image_Suspicious_URL",
                        "weight": WEIGHT_SUSPICIOUS_URL,
                        "desc":   f"Suspicious URL found in image data: {url.decode('latin-1', errors='ignore')[:100]}"
                    })

        except Exception as e:
            self.findings.append({
                "rule":   "Image_BinaryReadError",
                "weight": 0,
                "desc":   f"Binary analysis error (non-fatal): {e}"
            })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": "\n".join(extracted_notes),
            "threshold":      IMAGE_THRESHOLD
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
