#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    audit/audit_log.py
# Purpose: Simulates an immutable blockchain audit log.
# ──────────────────────────────────────────────────────────────────────

import json
from pathlib import Path

class AuditLog:
    def __init__(self, filename="audit_log.json"):
        self.filename = Path(filename)
        if not self.filename.exists():
            with open(self.filename, "w") as f:
                json.dump([], f)

    def append_record(self, record: dict):
        """Append a record to the JSON array."""
        with open(self.filename, "r") as f:
            data = json.load(f)
            
        data.append(record)
        
        with open(self.filename, "w") as f:
            json.dump(data, f, indent=2)

    def verify_record(self, index: int) -> dict:
        """Fetch a record by index."""
        with open(self.filename, "r") as f:
            data = json.load(f)
        return data[index]
