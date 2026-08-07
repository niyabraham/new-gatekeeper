import os

from core.scanners.macro_scanner import DocumentScanner
from core.scanners.pdf_scanner   import PDFScanner
from core.scanners.image_scanner import ImageScanner
from core.scanners.office_scanner import OfficeScanner
from core.scanners.email_scanner import EmailScanner
from core.scanners.text_scanner  import TextScanner

# ---------------------------------------------------------------------------
# Format routing table
# Maps file extensions to their scanner class and per-format threshold.
# Thresholds differ per format because threat severity and false-positive
# rates vary significantly across file types.
# ---------------------------------------------------------------------------

FORMAT_ROUTER = {
    # Macro-enabled Office documents — VBA execution risk
    ".xlsm": (DocumentScanner, 50),
    ".xls":  (DocumentScanner, 50),
    ".xlsb": (DocumentScanner, 50),
    ".xltm": (DocumentScanner, 50),
    ".doc":  (DocumentScanner, 50),
    ".docm": (DocumentScanner, 50),
    ".dotm": (DocumentScanner, 50),

    # PDF — JS/action execution risk, higher FP rate
    ".pdf":  (PDFScanner, 60),

    # Images — steganography / polyglot, rare threat
    ".jpg":  (ImageScanner, 65),
    ".jpeg": (ImageScanner, 65),
    ".png":  (ImageScanner, 65),

    # Open XML without macros — DDE, external links, embeds
    ".docx": (OfficeScanner, 55),
    ".xlsx": (OfficeScanner, 55),

    # Outlook email — phishing, malicious attachments
    ".msg":  (EmailScanner, 55),

    # Markdown / plain text — script injection, malicious links
    ".md":   (TextScanner, 70),
}


class FileRouter:
    def __init__(self, file_path: str):
        """
        Initialises the router for a single file.

        Determines the correct scanner class and per-format risk threshold
        based on the file extension. Raises an error for unsupported formats
        so the pipeline fails fast with a clear message.

        Args:
            file_path: Absolute or relative path to the file to scan.

        Raises:
            ValueError: If the file extension is not in FORMAT_ROUTER.
            FileNotFoundError: If the file does not exist.
        """
        self.file_path = os.path.abspath(file_path)

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        ext = os.path.splitext(self.file_path)[1].lower()
        if ext not in FORMAT_ROUTER:
            supported = ", ".join(sorted(FORMAT_ROUTER.keys()))
            raise ValueError(
                f"Unsupported file format: '{ext}'\n"
                f"Supported formats: {supported}"
            )

        self._scanner_class, self.threshold = FORMAT_ROUTER[ext]
        self.ext = ext

    @property
    def format_label(self) -> str:
        """
        Returns a human-readable label for the detected file format.

        Returns:
            String describing the document type (e.g. 'Excel Workbook').
        """
        labels = {
            ".xlsm": "Excel Workbook (Macro-enabled)",
            ".xls":  "Excel Workbook (Legacy)",
            ".xlsb": "Excel Workbook (Binary)",
            ".xltm": "Excel Template (Macro-enabled)",
            ".doc":  "Word Document (Legacy)",
            ".docm": "Word Document (Macro-enabled)",
            ".dotm": "Word Template (Macro-enabled)",
            ".pdf":  "PDF Document",
            ".jpg":  "JPEG Image",
            ".jpeg": "JPEG Image",
            ".png":  "PNG Image",
            ".docx": "Word Document (Open XML)",
            ".xlsx": "Excel Workbook (Open XML)",
            ".msg":  "Outlook Email Message",
            ".md":   "Markdown / Text Document",
        }
        return labels.get(self.ext, f"Unknown ({self.ext})")

    def get_scanner(self):
        """
        Instantiates and returns the correct scanner for this file.

        Returns:
            Scanner instance appropriate for the file's format.
        """
        return self._scanner_class(self.file_path)
