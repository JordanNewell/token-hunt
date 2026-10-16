from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from token_hunt.types import Match, Rule, ScanContext


def _fingerprint(value: str) -> str:
    """SHA-256 of value, first 16 chars. Used for allowlist + log dedup."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _pre_filter_passes(text: str, rule: Rule) -> bool:
    """If the rule has keywords, at least one must appear in text. Rules with
    no keywords always pass the pre-filter (they're universal patterns)."""
    if not rule.keywords:
        return True
    lower = text.lower()
    return any(kw.lower() in lower for kw in rule.keywords)


def scan_regex(text: str, rules: Iterable[Rule], ctx: ScanContext) -> list[Match]:
    """Run all regex rules against text. Returns one Match per hit."""
    matches: list[Match] = []
    lines = text.splitlines()

    for rule in rules:
        if not _pre_filter_passes(text, rule):
            continue
        try:
            pattern = re.compile(rule.regex)
        except re.error:
            continue  # bad regex in user rules — skip silently
        for line_no, line in enumerate(lines, start=1):
            for m in pattern.finditer(line):
                value = m.group(0)
                matches.append(Match(
                    kind=rule.id,
                    value=value,
                    fingerprint=_fingerprint(value),
                    rotate_url=rule.rotate_url,
                    detection_point=ctx.detection_point,
                    confidence=0.95,  # regex match = high confidence
                    rule_id=rule.id,
                    line=line_no,
                    column=m.start() + 1,
                ))
    return matches
