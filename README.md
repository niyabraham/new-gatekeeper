To help you present this project cleanly on GitHub and impress your lead during the review, here is a complete, production-ready **`README.md`** template. You can copy and paste this directly into a `README.md` file in your project root directory.

---

# 🛡️ Gatekeeper Security Pipeline

Gatekeeper is an advanced, object-oriented Python security pipeline designed to inspect, deobfuscate, score, and isolate macro-enabled Microsoft Excel workbooks (`.xlsm`, `.xls`) and legacy Excel 4.0 (XLM) sheets. It protects systems from weaponized Office documents using multi-layered static analysis, custom weighted rule engines, and automated quarantine triage.

---

## 🚀 Key Features & Lead's Suggestions Implemented

* **Modular Class-Based Architecture**: Fully structured object-oriented design separating scanning, deobfuscation, quarantine management, and pipeline orchestration.
* **Multi-Vector Threat Detection**:
* **VBA Macro Analysis**: Extracts and inspects embedded VBA source code using `olevba` (`oletools`).
* **Legacy XLM Inspection**: Parses hidden Excel 4.0 macro sheets via `XLMMacroDeobfuscator`.
* **Custom Rule Engine**: Evaluates structured pattern signatures from an externalized configuration (`rules/macro_rules.json`).
* **Keyword Co-occurrence Heuristic**: Detects chained risk indicators (e.g., combining shell execution and dynamic object instantiation).


* **String Deobfuscation Feedback Loop**: Automatically decodes Base64 payloads and obfuscated strings from extracted macro code, feeding findings back into the cumulative risk score.
* **Secure Quarantine & Triage**: Automatically isolates high-risk files into a secure directory (`quarantine/`) and supports forensic triage reporting via command-line arguments.
* **Crash-Safe Audit Logging**: Records compliance logs using high-performance, append-only **JSON Lines (`logs/audit_log.jsonl`)** to prevent file corruption during mid-write interruptions.

---

## 📂 Project Directory Structure

```text
NEW GATEKEEPER/
│
├── core/
│   ├── __init__.py
│   ├── pipeline.py            # End-to-end orchestration and audit logging
│   ├── scanner.py             # Multi-vector static analysis & rule matching
│   ├── deobfuscator.py        # String and Base64 payload reconstruction
│   └── quarantine_manager.py  # Isolation and CLI forensic triage
│
├── rules/
│   └── macro_rules.json       # Externalized detection rule definitions
│
├── logs/
│   └── audit_log.jsonl        # Crash-safe append-only compliance audit trail
│
├── quarantine/                # Isolated high-risk file storage
├── clean_output/              # Processed benign file archive
├── sample_files/              # Test samples (clean & malicious)
│
├── gatekeeper.py              # Main CLI entry point
├── requirements.txt           # Project dependencies
└── README.md                  # Project documentation

```

---

## ⚙️ Installation & Setup

1. **Clone the Repository**:
```powershell
git clone https://github.com/YOUR_USERNAME/NEW-GATEKEEPER.git
cd NEW-GATEKEEPER

```


2. **Install Dependencies**:
```powershell
python -m pip install -r requirements.txt

```



---

## 💻 Usage & Command-Line Interface

### 1. Scan a Document

Run the pipeline against an Excel workbook. If the risk score is $\ge 50$, the file is automatically quarantined; otherwise, it is safely copied to `clean_output/`.

```powershell
python gatekeeper.py sample_files\malicious_sample_1.xlsm

```

### 2. Triage Quarantined Threats

Inspect all isolated malicious files, reviewing their SHA-256 cryptographic hashes, file sizes, and quarantine status:

```powershell
python gatekeeper.py --triage

```

---

## 📊 Audit Logging (`logs/audit_log.jsonl`)

Every scan appends a structured JSON Line entry detailing the inspection timestamp, target filename, calculated risk score, final verdict (`CLEAN` or `BLOCKED`), destination path, and detailed finding breakdowns. Example entry:

```json
{
    "timestamp": "2026-07-24 11:26:54",
    "filename": "malicious_sample_1.xlsm",
    "file_path": "C:\\...\\sample_files\\malicious_sample_1.xlsm",
    "verdict": "BLOCKED",
    "risk_score": 200,
    "destination": "C:\\...\\quarantine\\malicious_sample_1_quarantined_20260724112654.xlsm",
    "findings_count": 7,
    "findings": [...]
}

```

---

## 🔍 Supported File Formats

Using the underlying parsing capabilities of `oletools`, Gatekeeper can be extended to inspect macro-enabled containers across the Microsoft Office suite, including:

* **Excel**: `.xlsm`, `.xls`, `.xlsb`, `.xltm`
* **Word**: `.doc`, `.docm`, `.dotm`
* **PowerPoint**: `.ppt`, `.pptm`, `.potm`
