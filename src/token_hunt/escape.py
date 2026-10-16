from __future__ import annotations

import re

from token_hunt.types import Match, ScanContext

# Patterns where bash evaluates a secret-bearing env var into emitted text.
# These leak the value even when the literal secret isn't in the input.
ESCAPE_PATTERNS = [
    # ${VAR:+...} and ${VAR:-...} — Jordan's bug class. Both branches can run.
    (re.compile(r'\$\{([A-Z][A-Z0-9_]{2,}):[+-][^\}]*\}'), "brace-eval"),
    # echo $TOKEN — direct echo of var
    (re.compile(r'\becho\s+["\']?\$([A-Z][A-Z0-9_]{2,})'), "echo-var"),
    # printenv TOKEN
    (re.compile(r'\bprintenv\s+([A-Z][A-Z0-9_]{2,})'), "printenv"),
    # env | grep X (likely hunting for a secret)
    (re.compile(r'\benv\b\s*\|\s*grep'), "env-pipe-grep"),
    # grep $VAR (variable expands before grep runs)
    (re.compile(r'\bgrep\s+.*\$([A-Z][A-Z0-9_]{2,})'), "grep-var"),
    # $(VAR) command substitution
    (re.compile(r'\$\(\s*([A-Z][A-Z0-9_]{2,})\s*\)'), "cmd-substitution"),
    # `VAR` backtick substitution
    (re.compile(r'`([A-Z][A-Z0-9_]{2,})`'), "backtick-substitution"),
    # printf with %s and secret arg
    (re.compile(r'\bprintf\s+.*%s.*\$([A-Z][A-Z0-9_]{2,})'), "printf-secret"),
    # awk ENVIRON access
    (re.compile(r'\bawk\b.*ENVIRON\['), "awk-environ"),
]

# Legit status-check patterns. If the SAME LINE has one of these, the escape
# pattern is treated as a safe check (not a leak).
SAFE_STATUS_PATTERNS = [
    re.compile(r'\[\s*-n\s'),                # [ -n "$VAR" ]
    re.compile(r'\[\s*-z\s'),                # [ -z "$VAR" ]
    re.compile(r'\bwc\s+-c\b'),              # wc -c <<< "$VAR"
    re.compile(r'\bwc\s+-m\b'),              # wc -m
    re.compile(r'\[\s*-n\s.*\]\s*&&\s*echo\s+(SET|UNSET|set|unset)'),
]

# Env var name patterns that mark a var as secret-bearing.
SECRET_NAME_SUFFIXES = (
    "_TOKEN", "_KEY", "_SECRET", "_API_KEY", "_PASSWORD", "_PASS",
    "_DBROOT", "_PAT", "_CREDENTIAL", "_CREDS", "_AUTH", "_ACCESS_KEY",
)
SECRET_NAME_PREFIXES = (
    "ANTHROPIC_", "OPENAI_", "GITHUB_", "ZCODE_", "Z_AI_", "FIGMA_",
    "LINEAR_", "STRIPE_", "SLACK_", "NPM_", "PYPI_", "HEROKU_",
    "AWS_", "GCP_", "AZURE_", "DBROOT", "TOKEN", "SECRET",
)


def _is_secret_var_name(name: str) -> bool:
    upper = name.upper()
    return any(upper.endswith(s) for s in SECRET_NAME_SUFFIXES) or any(
        upper.startswith(p) for p in SECRET_NAME_PREFIXES
    )


def _is_legit_status_check(line: str) -> bool:
    return any(p.search(line) for p in SAFE_STATUS_PATTERNS)


def scan_escape(text: str, ctx: ScanContext) -> list[Match]:
    """Detect bash patterns that evaluate secrets into emitted text.
    Only fires in PreToolUse:Bash context — escape patterns are bash-specific."""
    if ctx.detection_point != "PreToolUse:Bash":
        return []

    matches: list[Match] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _is_legit_status_check(line):
            continue
        for pattern, pattern_name in ESCAPE_PATTERNS:
            for m in pattern.finditer(line):
                var_name = m.group(1) if m.groups() else ""
                if var_name and not _is_secret_var_name(var_name):
                    continue
                kind = f"escape:{var_name}" if var_name else f"escape:{pattern_name}"
                matches.append(Match(
                    kind=kind,
                    value=line.strip(),  # the whole line, not the literal secret
                    fingerprint="",  # no literal secret to fingerprint
                    rotate_url="",
                    detection_point=ctx.detection_point,
                    confidence=0.85,
                    rule_id=f"escape:{pattern_name}",
                    line=line_no,
                    column=m.start() + 1,
                ))
    return matches
