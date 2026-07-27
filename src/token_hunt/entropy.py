from __future__ import annotations
import math
import re
from collections import Counter

from token_hunt.types import Match, ScanContext

MIN_LENGTH = 20
MIN_ENTROPY = 3.5  # hex keys are ~3.9; threshold below that keeps english prose out

# Word-boundary-ish token extraction. We look for runs of "secret-shaped" chars.
TOKEN_RE = re.compile(r'[A-Za-z0-9_+/=-]{20,}')


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_entropy(text: str, ctx: ScanContext) -> list[Match]:
    """Flag long high-entropy strings that didn't match a regex rule.
    Skipped for PreToolUse:Bash (commands have legit high-entropy args)."""
    if ctx.detection_point == "PreToolUse:Bash":
        return []

    matches: list[Match] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for m in TOKEN_RE.finditer(line):
            candidate = m.group(0)
            if len(candidate) < MIN_LENGTH:
                continue
            ent = shannon_entropy(candidate)
            if ent < MIN_ENTROPY:
                continue
            # Confidence scales with entropy above threshold
            confidence = min(0.4, 0.1 + (ent - MIN_ENTROPY) * 0.05)
            matches.append(Match(
                kind="entropy-candidate",
                value=candidate,
                fingerprint="",  # don't fingerprint unknowns
                rotate_url="",
                detection_point=ctx.detection_point,
                confidence=confidence,
                rule_id="entropy",
                line=line_no,
                column=m.start() + 1,
            ))
    return matches
