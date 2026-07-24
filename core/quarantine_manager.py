import os
import shutil
import hashlib
from datetime import datetime

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, file_path: str) -> str:
        """Isolates a malicious file by copying it into the quarantine directory."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File to quarantine not found: {file_path}")

        filename = os.path.basename(file_path)
        base_name, ext = os.path.splitext(filename)
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        target_filename = f"{base_name}_quarantined_{timestamp}{ext}"
        destination = os.path.join(self.quarantine_dir, target_filename)

        shutil.copy(file_path, destination)
        return destination

    def triage_quarantine(self) -> list:
        """Returns detailed dictionaries for files currently in quarantine for analyst review."""
        if not os.path.exists(self.quarantine_dir):
            return []
        
        reports = []
        for filename in os.listdir(self.quarantine_dir):
            file_path = os.path.join(self.quarantine_dir, filename)
            if os.path.isfile(file_path):
                sha256_hash = hashlib.sha256()
                try:
                    with open(file_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    file_hash = sha256_hash.hexdigest()
                except Exception:
                    file_hash = "N/A"

                reports.append({
                    "filename": filename,
                    "file_path": file_path,
                    "sha256_hash": file_hash,
                    "size_bytes": os.path.getsize(file_path),
                    "status": "Quarantined - Pending Analyst Review"
                })
        return reports