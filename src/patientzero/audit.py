"""Tamper-evident audit log.

Each record stores the hash of the record before it, like a chain.
If anyone edits or deletes a past record, verify() finds the broken link.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []
        self._lock = threading.Lock()
        self._last = GENESIS
        if self.path and self.path.exists():
            lines = self.path.read_text().splitlines()
            if lines:
                self._last = json.loads(lines[-1])["hash"]

    def write(self, **event) -> dict:
        with self._lock:
            record = {"ts": round(time.time(), 3), **event, "prev": self._last}
            record["hash"] = _digest(record)
            self._last = record["hash"]
            self.records.append(record)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(record) + "\n")
            return record


def verify(path: str | Path) -> tuple[bool, str]:
    """Check every link in the chain. Returns (ok, message)."""
    prev = GENESIS
    for n, line in enumerate(Path(path).read_text().splitlines(), start=1):
        record = json.loads(line)
        claimed = record.pop("hash")
        if record["prev"] != prev:
            return False, f"record {n}: chain broken (a record was removed or reordered)"
        if _digest(record) != claimed:
            return False, f"record {n}: contents were modified"
        prev = claimed
    return True, f"ok: {n if prev != GENESIS else 0} records verified"
