import re
import base64

class MacroDeobfuscator:
    def __init__(self, code_snippets=None):
        self.code_snippets = code_snippets or []

    def clean_strings(self, scan_results=None) -> list:
        """Cleans up common VBA obfuscation techniques like excessive concatenation or Chr() mappings."""
        snippets = list(self.code_snippets)
        
        # Dynamically extract snippets from scan findings if provided
        if scan_results and isinstance(scan_results, dict):
            for finding in scan_results.get("findings", []):
                desc = finding.get("desc", "")
                if desc:
                    snippets.append(desc)

        if not snippets:
            snippets = [""]

        cleaned_results = []
        
        for code in snippets:
            # 1. Strip out excessive underscore line continuations
            normalized_code = re.sub(r'_\s*\r?\n', '', code)
            
            # 2. Reconstruct basic string concatenations (e.g., "H" & "e" & "l" & "l" & "o" -> "Hello")
            normalized_code = re.sub(r'"\s*&\s*"', '', normalized_code)
            
            # 3. Detect potential base64 blobs inside the code
            base64_candidates = self._extract_base64_strings(normalized_code)
            
            cleaned_results.append({
                "original_snippet": code[:100] + "..." if len(code) > 100 else code,
                "normalized_code": normalized_code,
                "base64_artifacts": base64_candidates
            })
            
        return cleaned_results

    def _extract_base64_strings(self, text: str) -> list:
        """Finds potential base64 encoded payloads embedded within strings."""
        # Matches typical base64 strings of length 20 or more
        pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        matches = re.findall(pattern, text)
        decoded_strings = []
        
        for match in matches:
            try:
                # Attempt to decode to see if it reveals strings
                decoded_bytes = base64.b64decode(match)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                # Filter out unprintable binary junk
                if all(32 <= ord(c) < 127 for c in decoded_text if c not in '\r\n\t'):
                    decoded_strings.append({
                        "encoded": match,
                        "decoded": decoded_text
                    })
            except Exception:
                continue
                
        return decoded_strings