from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from token_hunt import regex_scanner
from token_hunt.allowlist import apply_allowlist
from token_hunt.entropy import scan_entropy
from token_hunt.escape import scan_escape
from token_hunt.patterns_loader import load_builtin_rules, load_user_rules
from token_hunt.types import Match, ScanContext


@dataclass(frozen=True)
class ScanResult:
    matches: list[Match]
    count: int
    highest_confidence: float


def _load_all_rules(ctx: ScanContext):
    """Load builtin + machine-local + repo-local rules. Later extends earlier."""
    rules = list(load_builtin_rules())
    home = Path.home()
    machine_local = home / ".token-hunt" / "patterns.local.toml"
    repo_local = Path(ctx.cwd) / ".token-hunt" / "patterns.local.toml"
    rules.extend(load_user_rules([machine_local, repo_local]))
    return rules


def scan(text: str, ctx: ScanContext) -> ScanResult:
    """Run all detection passes against text. Fail-closed: any internal
    exception propagates to caller (hook layer handles user-facing bypass)."""
    if not text:
        return ScanResult(matches=[], count=0, highest_confidence=0.0)

    rules = _load_all_rules(ctx)
    matches: list[Match] = []

    # Pass 1: regex rules (call via module so tests can monkeypatch)
    matches.extend(regex_scanner.scan_regex(text, rules, ctx))

    # Pass 2: bash escape hatch (only fires in PreToolUse:Bash)
    matches.extend(scan_escape(text, ctx))

    # Pass 3: entropy candidates (skipped for Bash)
    matches.extend(scan_entropy(text, ctx))

    # Apply allowlist filters
    matches = apply_allowlist(matches, ctx)

    highest = max((m.confidence for m in matches), default=0.0)
    return ScanResult(matches=matches, count=len(matches), highest_confidence=highest)
