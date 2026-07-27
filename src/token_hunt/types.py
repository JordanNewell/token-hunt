from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""
    id: str
    regex: str  # raw regex pattern as string (compiled at scan time)
    description: str = ""
    keywords: tuple[str, ...] = ()
    rotate_url: str = ""


@dataclass(frozen=True)
class Match:
    """A detection. value kept in memory only, never written to disk."""
    kind: str  # rule id or "escape-hatch" or "entropy-candidate"
    value: str
    fingerprint: str  # SHA-256 first 16 chars
    rotate_url: str
    detection_point: str  # "UserPromptSubmit", "PostToolUse:Read", etc.
    confidence: float
    rule_id: str  # which rule or pattern fired
    line: int = 0
    column: int = 0


@dataclass(frozen=True)
class ScanContext:
    """Context for a scan pass."""
    detection_point: str
    cwd: str = "."
    file_path: str | None = None  # set for Read/Write scans
    env_allow: tuple[str, ...] = ()  # TOKEN_HUNT_ALLOW-style overrides
