from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


OVERDUE_HOURS = 72  # matches feedback_security-md-fleet-conventions


@dataclass
class LeakRecord:
    """One row in rotations.log."""
    id: Optional[int]
    ts: str  # ISO 8601 UTC
    kind: str
    source: str  # detection_point
    fingerprint: str  # SHA-256 first 16 chars, or "" for escape patterns
    rotate_url: str
    status: str  # "open" or "closed"
    note: str = ""

    @property
    def is_overdue(self) -> bool:
        try:
            ts = datetime.fromisoformat(self.ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return False
        age = datetime.now(timezone.utc) - ts
        return age > timedelta(hours=OVERDUE_HOURS) and self.status == "open"


class Store:
    """JSONL append-only store at ~/.token-hunt/rotations.log."""

    def __init__(self):
        self.path = Path.home() / ".token-hunt" / "rotations.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _next_id(self) -> int:
        """Max existing id + 1. Scans file each call — fine for low volume."""
        max_id = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                max_id = max(max_id, rec.get("id", 0))
            except json.JSONDecodeError:
                continue
        return max_id + 1

    def append(self, record: LeakRecord) -> int:
        leak_id = self._next_id()
        record.id = leak_id
        line = json.dumps(asdict(record), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return leak_id

    def list_open(self) -> list[LeakRecord]:
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("status") == "open":
                records.append(LeakRecord(**rec))
        return records

    def close(self, leak_id: int, note: str = "") -> bool:
        """Rewrite rotations.log with the given id marked closed. Returns True
        if a record was found and updated."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        changed = False
        out = []
        for line in lines:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                out.append(line)
                continue
            if rec.get("id") == leak_id:
                rec["status"] = "closed"
                if note:
                    rec["note"] = note
                changed = True
            out.append(json.dumps(rec, ensure_ascii=False))
        if changed:
            self.path.write_text("\n".join(out) + "\n", encoding="utf-8")
        return changed
