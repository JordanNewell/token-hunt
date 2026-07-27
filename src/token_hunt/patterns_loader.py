from __future__ import annotations
import sys
from pathlib import Path
from typing import Iterable

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from token_hunt.types import Rule

BUILTIN_PATTERNS_DIR = Path(__file__).parent / "patterns"


def load_rules_from_path(path: Path) -> list[Rule]:
    """Load rules from a single TOML file. Raises ValueError on invalid TOML."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"invalid TOML in {path}: {e}") from e

    rules = []
    for entry in data.get("rules", []):
        keywords = tuple(entry.get("keywords", []))
        rules.append(Rule(
            id=entry["id"],
            regex=entry["regex"],
            description=entry.get("description", ""),
            keywords=keywords,
            rotate_url=entry.get("rotate_url", ""),
        ))
    return rules


def load_builtin_rules() -> list[Rule]:
    """Load the builtin pattern set shipped with the package."""
    return load_rules_from_path(BUILTIN_PATTERNS_DIR / "builtin.toml")


def load_user_rules(paths: Iterable[Path]) -> list[Rule]:
    """Load rules from machine-local + repo-local TOML files. Missing files OK."""
    rules: list[Rule] = []
    for p in paths:
        if p.is_file():
            rules.extend(load_rules_from_path(p))
    return rules
