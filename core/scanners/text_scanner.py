import os
import re

# ---------------------------------------------------------------------------
# Text / Markdown scanner risk weight constants
# ---------------------------------------------------------------------------

WEIGHT_MALICIOUS_LINK        = 35  # Link to high-risk domain
WEIGHT_SCRIPT_INJECTION      = 50  # Inline HTML script tag
WEIGHT_SHELL_COMMAND         = 40  # Shell command in code block
WEIGHT_SUSPICIOUS_URL        = 25  # URL with suspicious TLD
WEIGHT_ENCODED_PAYLOAD       = 45  # Base64 or encoded content
WEIGHT_CREDENTIAL_PATTERN    = 30  # Credential-like patterns
WEIGHT_IP_ADDRESS_LINK       = 35  # Direct IP address link (bypasses DNS)
WEIGHT_REDIRECT_CHAIN        = 25  # URL shortener / redirect chain

TEXT_THRESHOLD = 70  # Highest threshold — .md is lowest risk format

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".pw", ".top",
    ".xyz", ".club", ".ml", ".ga", ".cf",
    ".icu", ".work", ".online"
}

# URL shorteners and redirect services
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "tiny.cc", "cli.gs", "url4.eu"
]

# Shell commands that should not appear in documentation
DANGEROUS_SHELL_COMMANDS = [
    r'wget\s+http',          # Download via wget
    r'curl\s+http',          # Download via curl
    r'powershell\s+-',       # PowerShell with flags
    r'cmd\.exe\s+/c',        # CMD execution
    r'bash\s+-c',            # Bash command execution
    r'eval\s*\$\(',          # Bash eval
    r'python\s+-c\s+["\']import', # Python one-liner import
    r'base64\s+--decode',    # Base64 decode pipe
    r'chmod\s+\+x',         # Make file executable
    r'\.\/[a-zA-Z]+',        # Execute local file
    r'nc\s+-[lnvz]',         # Netcat listener
    r'rm\s+-rf\s+/',         # Destructive rm command
]

# Patterns that indicate credential exposure
CREDENTIAL_PATTERNS = [
    r'password\s*[=:]\s*\S+',
    r'passwd\s*[=:]\s*\S+',
    r'api[_-]?key\s*[=:]\s*\S+',
    r'secret[_-]?key\s*[=:]\s*\S+',
    r'access[_-]?token\s*[=:]\s*\S+',
    r'private[_-]?key\s*[=:]\s*\S+',
    r'aws[_-]?secret\s*[=:]\s*\S+',
    r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
]


class TextScanner:
    def __init__(self, file_path: str):
        """
        Initialises the text/markdown scanner for a single .md file.

        Args:
            file_path: Absolute path to the .md file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs deep static analysis of a Markdown or plain text file.

        Analysis covers:
            1. URL and link analysis — extracts all URLs and checks for
               suspicious TLDs, direct IP links, and URL shorteners
            2. Script injection detection — finds inline HTML script tags
               and JavaScript that could execute in rendered markdown
            3. Shell command analysis — scans code blocks for dangerous
               commands that could be copied and executed by readers
            4. Credential pattern detection — identifies accidentally
               committed secrets, API keys, and private keys

        Text threshold is highest (70) — markdown is the lowest risk
        format and requires the most evidence before blocking.

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            self.findings.append({
                "rule":   "Text_ReadError",
                "weight": 10,
                "desc":   f"Could not read file: {e}"
            })
            return {
                "risk_score":     self.risk_score,
                "findings":       self.findings,
                "extracted_code": "",
                "threshold":      TEXT_THRESHOLD
            }

        content_lower = content.lower()
        extracted_text = content[:500]

        # ----------------------------------------------------------------
        # Layer 1: URL and link analysis
        # ----------------------------------------------------------------
        urls = re.findall(r'https?://[^\s\'")\]>]+', content)

        for url in set(urls):
            url_lower = url.lower()

            # Direct IP address link (bypasses DNS — suspicious)
            if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                self._add_unique({
                    "rule":   "Text_Direct_IP_Link",
                    "weight": WEIGHT_IP_ADDRESS_LINK,
                    "desc":   f"Direct IP address URL found: {url[:100]} — bypasses DNS resolution."
                })

            # Suspicious TLD
            elif any(tld in url_lower for tld in SUSPICIOUS_TLDS):
                self._add_unique({
                    "rule":   "Text_Suspicious_URL",
                    "weight": WEIGHT_SUSPICIOUS_URL,
                    "desc":   f"URL with high-risk TLD: {url[:100]}"
                })

            # URL shortener
            elif any(shortener in url_lower for shortener in URL_SHORTENERS):
                self._add_unique({
                    "rule":   "Text_URL_Shortener",
                    "weight": WEIGHT_REDIRECT_CHAIN,
                    "desc":   f"URL shortener detected: {url[:100]} — destination is obfuscated."
                })

        # Markdown-style links: [text](url)
        md_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        for link_text, link_url in md_links:
            # Mismatched link text vs actual URL (phishing indicator)
            if ("http" in link_text.lower() and "http" in link_url):
                text_domain = re.search(r'https?://([^/\s]+)', link_text)
                url_domain  = re.search(r'https?://([^/\s]+)', link_url)
                if text_domain and url_domain:
                    if text_domain.group(1) != url_domain.group(1):
                        self._add_unique({
                            "rule":   "Text_Misleading_Link",
                            "weight": WEIGHT_MALICIOUS_LINK,
                            "desc":   (
                                f"Misleading link: text shows '{text_domain.group(1)}' "
                                f"but points to '{url_domain.group(1)}'"
                            )
                        })

        # ----------------------------------------------------------------
        # Layer 2: Script injection detection
        # ----------------------------------------------------------------
        script_patterns = [
            (r'<script[^>]*>',                   "HTML script tag in markdown"),
            (r'javascript\s*:',                   "JavaScript protocol URL"),
            (r'onload\s*=',                       "HTML event handler (onload)"),
            (r'onerror\s*=',                      "HTML event handler (onerror)"),
            (r'<iframe[^>]*>',                    "HTML iframe tag"),
            (r'<object[^>]*>',                    "HTML object tag"),
        ]

        for pattern, description in script_patterns:
            if re.search(pattern, content_lower):
                self._add_unique({
                    "rule":   "Text_Script_Injection",
                    "weight": WEIGHT_SCRIPT_INJECTION,
                    "desc":   f"Script injection: {description}"
                })

        # ----------------------------------------------------------------
        # Layer 3: Shell command analysis in code blocks
        # ----------------------------------------------------------------
        code_blocks = re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL)
        inline_code = re.findall(r'`([^`]+)`', content)
        all_code    = "\n".join(code_blocks + inline_code)

        for pattern in DANGEROUS_SHELL_COMMANDS:
            if re.search(pattern, all_code, re.IGNORECASE):
                self._add_unique({
                    "rule":   "Text_Dangerous_Command",
                    "weight": WEIGHT_SHELL_COMMAND,
                    "desc":   f"Dangerous shell command pattern '{pattern}' found in code block."
                })

        # ----------------------------------------------------------------
        # Layer 4: Credential and secret detection
        # ----------------------------------------------------------------
        for pattern in CREDENTIAL_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                self._add_unique({
                    "rule":   "Text_Credential_Exposure",
                    "weight": WEIGHT_CREDENTIAL_PATTERN,
                    "desc":   f"Potential credential exposure: '{match.group(0)[:60]}'"
                })

        # Base64 encoded blocks in markdown
        b64_pattern = r'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        b64_matches = re.findall(b64_pattern, content)
        if len(b64_matches) >= 2:
            self._add_unique({
                "rule":   "Text_Encoded_Payload",
                "weight": WEIGHT_ENCODED_PAYLOAD,
                "desc":   f"Multiple large base64 blocks found ({len(b64_matches)}) — possible encoded payload."
            })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      TEXT_THRESHOLD
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
