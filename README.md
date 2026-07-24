Gatekeeper is an advanced, object-oriented Python security pipeline designed to inspect, deobfuscate, score, and isolate macro-enabled Microsoft Excel workbooks (.xlsm, .xls) and legacy Excel 4.0 (XLM) sheets. It protects systems from weaponized Office documents using multi-layered static analysis, custom weighted rule engines, and automated quarantine triage.

```markdown


## End-to-End System Workflow


[ gatekeeper.py ] (CLI Controller)
       │
       ├── Mode: --triage ──> [ QuarantineManager.triage_quarantine() ] ──> Prints Report
       │
       └── Mode: File Scan ──> [ GatekeeperPipeline.run() ]
                                   │
                                   ├── 1. DocumentScanner.analyze()
                                   │       ├── VBA Macro Extraction (olevba)
                                   │       ├── XLM Macro Sheet Analysis (XLMMacroDeobfuscator)
                                   │       ├── Custom Rule Matching (rules/macro_rules.json)
                                   │       └── Keyword Co-occurrence Heuristic
                                   │
                                   ├── 2. MacroDeobfuscator.clean_strings()
                                   │       └── Base64 / String Reconstruction & Feedback Loop
                                   │
                                   ├── 3. Risk Scoring & Routing
                                   │       ├── Risk Score >= 50 ──> BLOCKED ──> QuarantineManager.quarantine_file()
                                   │       └── Risk Score < 50  ──> CLEAN   ──> Copies to clean_output/
                                   │
                                   └── 4. Crash-Safe Audit Logging (logs/audit_log.jsonl)

```

---

##  Project Directory Structure

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

##  Detailed Component & Code Logic Breakdown

### 1. `gatekeeper.py` (CLI Controller)

* **Purpose**: Serves as the primary command-line entry point for users and automated scripts.
* **Code Logic**: Uses Python's `argparse` module to handle execution flags. If the `--triage` flag is provided, it invokes `QuarantineManager.triage_quarantine()` and prints a formatted summary table of all quarantined threats. Otherwise, it extracts the target file path, initializes `GatekeeperPipeline`, and triggers the analysis.

### 2. `core/pipeline.py` (`GatekeeperPipeline` Class)

* **Purpose**: Orchestrates the entire security pipeline from ingestion to auditing.
* **Key Functions**:
* `__init__(file_path)`: Resolves absolute file paths, initializes component managers, and sets up the absolute path for the audit log (`logs/audit_log.jsonl`).
* `_log_audit(...)`: Implements crash-safe JSON Lines (`jsonl`) logging. It serializes timestamp, filename, verdict, risk score, findings, and destination into a single-line JSON string and appends it to `audit_log.jsonl`.
* `run()`: Executes the core workflow: calls the scanner, passes the code corpus to the deobfuscator for string reconstruction, folds discoveries back into the risk score, routes files to `clean_output/` or `quarantine/`, writes the audit log entry, and returns the scan summary dictionary.



### 3. `core/scanner.py` (`DocumentScanner` Class)

* **Purpose**: Performs deep, multi-vector static analysis on the workbook.
* **Key Functions**:
* `_load_custom_rules()`: Reads structured signature patterns and risk weights from `rules/macro_rules.json`.
* `analyze()`:
1. **VBA Parsing (`olevba`)**: Detects active macros, extracts VBA code streams into an `extracted_code_corpus`, evaluates keywords, and assigns weighted scores (e.g., 30 for auto-execute triggers and dangerous API calls like `Shell` or `CreateObject`, 10 for standard keywords).
2. **XLM Parsing (`XLMMacroDeobfuscator`)**: Checks for legacy Excel 4.0 workspace macro sheets or hidden formulas.
3. **Custom Rule Matching**: Scans the extracted code corpus against patterns defined in `macro_rules.json`.
4. **Keyword Co-occurrence Heuristic**: Evaluates code blocks for chained risk indicators (combining triggers like `shell`, `environ`, and `powershell`) to catch advanced threats.





### 4. `core/deobfuscator.py` (`MacroDeobfuscator` Class)

* **Purpose**: Reconstructs hidden strings, encoded blocks, and obfuscated variables.
* **Key Functions**:
* `clean_strings()`: Scans code snippets for Base64 or obfuscated string patterns, decodes payloads, and extracts plaintext indicators to feed back into the pipeline's risk scoring engine.



### 5. `core/quarantine_manager.py` (`QuarantineManager` Class)

* **Purpose**: Manages threat isolation and forensic reporting.
* **Key Functions**:
* `quarantine_file(file_path)`: Generates a unique, timestamped filename and copies the malicious workbook into the `quarantine/` directory.
* `triage_quarantine()`: Iterates through all files in the quarantine folder, computes their SHA-256 cryptographic hashes and file sizes, and returns a structured list of dictionaries containing file metadata and status (`Quarantined - Pending Analyst Review`) for analyst review.



---

##  Installation & Setup

1. **Clone the Repository**:
```powershell
git clone [https://github.com/niyabraham/new-gatekeeper.git](https://github.com/niyabraham/new-gatekeeper.git)
cd NEW-GATEKEEPER

```


2. **Install Dependencies**:
```powershell
python -m pip install -r requirements.txt

```



---

##  Command-Line Usage

### 1. Scan a Document

Run the pipeline against an Excel workbook. If the cumulative risk score is $\ge 50$, the file is automatically blocked and quarantined; otherwise, it is safely archived in `clean_output/`.

```powershell
python gatekeeper.py sample_files\malicious_sample_1.xlsm

```

### 2. Triage Quarantined Threats

Inspect all isolated malicious files, reviewing their SHA-256 cryptographic hashes, file sizes, and quarantine status:

```powershell
python gatekeeper.py --triage

```

---

## Compliance Audit Logging (`logs/audit_log.jsonl`)

Every scan appends an immutable JSON Line record detailing the execution timestamp, target file, calculated risk score, verdict (`CLEAN` or `BLOCKED`), destination path, and findings breakdown. Example entry:

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

##  Supported File Formats

Using the underlying parsing capabilities of `oletools`, Gatekeeper can be extended to inspect macro-enabled containers across the Microsoft Office suite, including:

* **Excel**: `.xlsm`, `.xls`, `.xlsb`, `.xltm`
* **Word**: `.doc`, `.docm`, `.dotm`
* **PowerPoint**: `.ppt`, `.pptm`, `.potm`

```

```
