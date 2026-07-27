from __future__ import annotations
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from token_hunt.types import Match, ScanContext

# Path patterns that commonly contain realistic fake keys (test fixtures etc.)
# Mirrors Jordan's existing ~/.gitleaks-config.toml allowlist.
ALLOWED_PATH_PATTERNS = [
    re.compile(p) for p in [
        r'(^|/)node_modules/.*',
        r'(^|/)vendor/.*',
        r'(^|/)third_party/.*',
        r'(^|/)tests?/fixtures?/.*',
        r'(^|/)tests?/.*\.example$',
        r'(^|/)examples?/.*',
        r'(^|/)samples?/.*',
        r'(^|/)demo/.*',
        r'.*\.example$',
        r'.*\.sample$',
        r'.*\.env\.sample$',
        r'.*\.env\.example$',
        r'.*_test\..*',
        r'.*\.test\..*',
        r'.*\.spec\..*',
    ]
]


def is_path_allowed(path: str) -> bool:
    return any(p.search(path) for p in ALLOWED_PATH_PATTERNS)


def load_fingerprint_allowlist() -> set[str]:
    """Load SHA-256 fingerprints from ~/.token-hunt/allowlist.toml.
    Missing file = empty allowlist."""
    home = Path.home()
    allowlist_file = home / ".token-hunt" / "allowlist.toml"
    if not allowlist_file.is_file():
        return set()
    try:
        data = tomllib.loads(allowlist_file.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return set()
    return set(data.get("fingerprints", []))


def apply_allowlist(matches: list[Match], ctx: ScanContext) -> list[Match]:
    """Filter out allowlisted matches."""
    if not matches:
        return matches

    # Path-based allowlist (only applies to file-backed scans)
    if ctx.file_path and is_path_allowed(ctx.file_path):
        return []

    # Fingerprint-based allowlist
    allowed_fps = load_fingerprint_allowlist()
    if not allowed_fps:
        return matches

    return [m for m in matches if m.fingerprint not in allowed_fps]
