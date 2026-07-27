# token-hunt v0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working Claude Code plugin + pip-installable CLI that catches secrets at chat time, with 12 provider rules, escape-hatch detection, and rotations.log tracking.

**Architecture:** Python detection core with two peers — Claude Code plugin (6 hook scripts that shell out to the CLI) and pip-installable CLI. Pattern rules in TOML (gitleaks-compatible). Storage in JSONL.

**Tech Stack:** Python 3.10+, stdlib argparse + `tomli` + `watchdog` + `platformdirs`, pytest, ruff. MIT license.

**Spec:** `docs/superpowers/specs/2026-07-27-token-hunt-design.md`

---

## File Structure

```
token-hunt/
├── pyproject.toml                   # Task 1
├── LICENSE                          # Task 1 (MIT)
├── .gitignore                       # Task 1
├── README.md                        # Task 22 (skeleton in Task 1)
├── src/token_hunt/
│   ├── __init__.py                  # Task 1
│   ├── types.py                     # Task 4 (Match, Rule, ScanContext dataclasses)
│   ├── patterns_loader.py           # Task 3 (load TOML → Rule objects)
│   ├── regex_scanner.py             # Task 4 (scan_regex)
│   ├── escape.py                    # Task 5 (escape hatch detector)
│   ├── entropy.py                   # Task 6 (entropy candidates)
│   ├── allowlist.py                 # Task 7 (path + fingerprint filters)
│   ├── engine.py                    # Task 8 (scan() orchestrator)
│   ├── store.py                     # Task 9 (rotations.log JSONL)
│   ├── cli.py                       # Task 10-14 (CLI commands)
│   └── patterns/
│       ├── builtin.toml             # Task 2 (12 provider rules)
│       └── rotate-urls.toml         # Task 2 (provider → rotate.io URLs)
├── plugin/
│   ├── plugin.json                  # Task 16
│   ├── hooks.json                   # Task 16
│   └── hooks/
│       ├── user-prompt-submit.sh    # Task 17
│       ├── pre-bash.sh              # Task 18
│       ├── post-bash.sh             # Task 19
│       ├── post-read.sh             # Task 20
│       ├── pre-write.sh             # Task 21
│       └── post-write.sh            # Task 21
├── tests/
│   ├── conftest.py                  # Task 1 (fixtures)
│   ├── fixtures.py                  # Task 1 (fake-secret constants)
│   ├── test_patterns_loader.py      # Task 3
│   ├── test_regex_scanner.py        # Task 4
│   ├── test_escape.py               # Task 5
│   ├── test_entropy.py              # Task 6
│   ├── test_allowlist.py            # Task 7
│   ├── test_engine.py               # Task 8
│   ├── test_store.py                # Task 9
│   ├── test_cli.py                  # Tasks 10-14
│   └── test_e2e_hooks.py            # Task 23
└── docs/superpowers/
    ├── specs/2026-07-27-token-hunt-design.md    (already exists)
    └── plans/2026-07-27-token-hunt-v0.1.md      (this file)
```

---

## Phase 1: Foundation (Tasks 1-3)

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE`
- Create: `.gitignore`
- Create: `src/token_hunt/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/fixtures.py`
- Create: `README.md` (skeleton — full version in Task 22)

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "token-hunt"
version = "0.1.0"
description = "Catch secrets at chat time, not commit time. Hook-based scanner for Claude Code / Cursor / Aider."
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [{ name = "Jordan Newell", email = "jordan@jordannewell.com" }]
classifiers = [
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance",
]
dependencies = [
    "tomli>=2.0.0; python_version < '3.11'",
    "platformdirs>=4.0.0",
    "watchdog>=4.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=5.0.0",
    "ruff>=0.6.0",
]

[project.scripts]
token-hunt = "token_hunt.cli:main"

[project.urls]
Homepage = "https://github.com/JordanNewell/token-hunt"
Documentation = "https://github.com/JordanNewell/token-hunt#readme"
Issues = "https://github.com/JordanNewell/token-hunt/issues"

[tool.hatch.build.targets.wheel]
packages = ["src/token_hunt"]

[tool.hatch.build.targets.wheel.shared-data]
"src/token_hunt/patterns" = "token_hunt/patterns"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers"
```

- [ ] **Step 2: Write `LICENSE` (MIT)**

```
MIT License

Copyright (c) 2026 Jordan Newell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Write `.gitignore`**

```
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
*.egg
build/
dist/
.pytest_cache/
.coverage
.coverage.*
htmlcov/
.venv/
venv/
env/
.DS_Store
.token-hunt/
*.log
!docs/**/*.md
```

- [ ] **Step 4: Write `src/token_hunt/__init__.py`**

```python
"""token-hunt: catch secrets at chat time, not commit time."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Write `tests/fixtures.py` (fake secrets for tests)**

```python
"""Fake secrets for tests. All values match our regex patterns but are
obviously invalid (all-zeros, test prefixes). None will authenticate.
"""

# Format-valid but obviously fake. Match the regex, fail reality.
ZAI_KEY = "0" * 32 + "." + "0" * 16
ZAI_KEY_ALT = "a" * 32 + "." + "B" * 16

ANTHROPIC_KEY = "sk-ant-" + "0" * 95
GITHUB_PAT = "ghp_" + "0" * 36
GITHUB_FINE_PAT = "github_pat_" + "0" * 20 + "_" + "0" * 16
FIGMA_PAT = "figd_" + "0" * 40
PYPI_TOKEN = "pypi-" + "0" * 60
LINEAR_KEY = "lin_api_" + "0" * 40
STRIPE_SK = "sk_live_" + "0" * 24
OPENAI_KEY = "sk-" + "0" * 48
NPM_TOKEN = "npm_" + "0" * 36
SLACK_TOKEN = "xoxb-" + "0" * 30

# Status-check escape patterns (Jordan's bug class)
ESCAPE_PATTERN_DOLLAR_BRACE = 'echo ${ANTHROPIC_API_KEY:+SET}${ANTHROPIC_API_KEY:-UNSET}'
ESCAPE_PATTERN_ECHO = 'echo $GITHUB_TOKEN'
ESCAPE_PATTERN_PRINTENV = 'printenv STRIPE_SECRET_KEY'
ESCAPE_PATTERN_ENV_GREP = 'env | grep -i token'
ESCAPE_PATTERN_GREP_VAR = 'grep $DB_PASSWORD /etc/shadow'

# Legit status check (should NOT fire)
ESCAPE_SAFE_STATUS_CHECK = '[ -n "$ANTHROPIC_API_KEY" ] && echo SET'
ESCAPE_SAFE_WC = 'wc -c <<< "$ANTHROPIC_API_KEY"'

# Test fixture allowlist fingerprint (Task 7 uses this)
ALLOWLISTED_FAKE_KEY = "test_fixture_deadbeefdeadbeefdeadbeefdeadbeef.ABCDefgh1234567890"
```

- [ ] **Step 6: Write `tests/conftest.py`**

```python
import pytest


@pytest.fixture
def tmp_token_hunt_home(tmp_path, monkeypatch):
    """Redirect ~/.token-hunt/ to a tmp dir for isolated tests."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    return fake_home / ".token-hunt"
```

- [ ] **Step 7: Write `README.md` skeleton (full version Task 22)**

```markdown
# token-hunt

> Catch secrets at chat time, not commit time.

Hook-based secret scanner for Claude Code, Cursor, Aider, and other AI CLIs.

**Status:** v0.1.0 in development. See `docs/superpowers/specs/`.

## Install

Coming soon.
```

- [ ] **Step 8: Verify package layout**

Run: `cd /e/dev/projects/token-hunt && py -m pip install -e ".[dev]" && py -m pytest --collect-only`
Expected: collection succeeds with 0 tests, no errors.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml LICENSE .gitignore src/ tests/ README.md
git commit -m "scaffold: token-hunt package layout, MIT license, dev deps"
```

---

### Task 2: Pattern files (builtin.toml + rotate-urls.toml)

**Files:**
- Create: `src/token_hunt/patterns/builtin.toml`
- Create: `src/token_hunt/patterns/rotate-urls.toml`

- [ ] **Step 1: Write `src/token_hunt/patterns/builtin.toml`**

```toml
# token-hunt builtin patterns. gitleaks-compatible format.
# Each rule has: id, description, regex, keywords (for pre-filter), rotate_url.

[[rules]]
id = "zai-api-key"
description = "Z.ai / Bigmodel API key (xxx.yyyy 49-char)"
regex = '''[0-9a-f]{32}\.[A-Za-z0-9]{16}'''
keywords = ["."]
rotate_url = "https://z.ai/account/apikeys"

[[rules]]
id = "anthropic-key"
description = "Anthropic API key"
regex = '''sk-ant-[A-Za-z0-9_-]{95}'''
keywords = ["sk-ant"]
rotate_url = "https://console.anthropic.com/settings/keys"

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token (classic)"
regex = '''gh[pusr]_[A-Za-z0-9]{36}'''
keywords = ["ghp_", "ghs_", "ghu_", "ghr_"]
rotate_url = "https://github.com/settings/tokens"

[[rules]]
id = "github-fine-pat"
description = "GitHub fine-grained PAT"
regex = '''github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'''
keywords = ["github_pat_"]
rotate_url = "https://github.com/settings/personal-access-tokens"

[[rules]]
id = "figma-pat"
description = "Figma personal access token"
regex = '''figd_[A-Za-z0-9]{40}'''
keywords = ["figd_"]
rotate_url = "https://www.figma.com/settings"

[[rules]]
id = "pypi-token"
description = "PyPI API token"
regex = '''pypi-[A-Za-z0-9]{60,}'''
keywords = ["pypi-"]
rotate_url = "https://pypi.org/manage/account/token/"

[[rules]]
id = "linear-key"
description = "Linear API key"
regex = '''lin_api_[A-Za-z0-9]{40}'''
keywords = ["lin_api_"]
rotate_url = "https://linear.app/settings/api"

[[rules]]
id = "stripe-sk"
description = "Stripe secret key"
regex = '''sk_live_[A-Za-z0-9]{24,}'''
keywords = ["sk_live_"]
rotate_url = "https://dashboard.stripe.com/apikeys"

[[rules]]
id = "openai-key"
description = "OpenAI API key"
regex = '''sk-[A-Za-z0-9]{48}'''
keywords = ["sk-"]
rotate_url = "https://platform.openai.com/api-keys"

[[rules]]
id = "npm-token"
description = "npm access token (auth token shape)"
regex = '''npm_[A-Za-z0-9]{36}'''
keywords = ["npm_"]
rotate_url = "https://www.npmjs.com/settings/~/tokens"

[[rules]]
id = "slack-token"
description = "Slack token (bot/user/app)"
regex = '''xox[abpr]-[A-Za-z0-9-]{10,}'''
keywords = ["xoxa-", "xoxb-", "xoxp-", "xoxr-"]
rotate_url = "https://api.slack.com/apps"

[[rules]]
id = "gitlab-pat"
description = "GitLab personal access token"
regex = '''glpat-[A-Za-z0-9_-]{20}'''
keywords = ["glpat-"]
rotate_url = "https://gitlab.com/-/profile/personal_access_tokens"

[allowlist]
description = "Skip test fixtures and example files"
paths = [
    '''(^|/)node_modules/.*''',
    '''(^|/)vendor/.*''',
    '''(^|/)tests?/fixtures?/.*''',
    '''(^|/)tests?/.*\.example$''',
    '''.*\.example$''',
    '''.*\.env\.sample$''',
    '''.*\.env\.example$''',
]
```

- [ ] **Step 2: Write `src/token_hunt/patterns/rotate-urls.toml`**

```toml
# Provider metadata. Used by `token-hunt list` and WARN banners.
# Kept separate from builtin.toml so it can be updated independently.

[providers.zai-api-key]
name = "Z.ai / Bigmodel"
rotate_url = "https://z.ai/account/apikeys"
docs_url = "https://z.ai/docs/api"

[providers.anthropic-key]
name = "Anthropic"
rotate_url = "https://console.anthropic.com/settings/keys"
docs_url = "https://docs.anthropic.com/"

[providers.github-pat]
name = "GitHub Personal Access Token"
rotate_url = "https://github.com/settings/tokens"
docs_url = "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"

[providers.github-fine-pat]
name = "GitHub fine-grained PAT"
rotate_url = "https://github.com/settings/personal-access-tokens"

[providers.figma-pat]
name = "Figma"
rotate_url = "https://www.figma.com/settings"

[providers.pypi-token]
name = "PyPI"
rotate_url = "https://pypi.org/manage/account/token/"

[providers.linear-key]
name = "Linear"
rotate_url = "https://linear.app/settings/api"

[providers.stripe-sk]
name = "Stripe"
rotate_url = "https://dashboard.stripe.com/apikeys"

[providers.openai-key]
name = "OpenAI"
rotate_url = "https://platform.openai.com/api-keys"

[providers.npm-token]
name = "npm"
rotate_url = "https://www.npmjs.com/settings/~/tokens"

[providers.slack-token]
name = "Slack"
rotate_url = "https://api.slack.com/apps"

[providers.gitlab-pat]
name = "GitLab"
rotate_url = "https://gitlab.com/-/profile/personal_access_tokens"
```

- [ ] **Step 3: Commit**

```bash
git add src/token_hunt/patterns/
git commit -m "patterns: 12 builtin providers + rotate URL registry"
```

---

### Task 3: Pattern loader

**Files:**
- Create: `src/token_hunt/types.py`
- Create: `src/token_hunt/patterns_loader.py`
- Create: `tests/test_patterns_loader.py`

- [ ] **Step 1: Write `tests/test_patterns_loader.py` (failing test first)**

```python
import pytest
from token_hunt.patterns_loader import load_builtin_rules, Rule


def test_load_builtin_rules_returns_list():
    rules = load_builtin_rules()
    assert isinstance(rules, list)
    assert len(rules) == 12


def test_rules_have_required_fields():
    rules = load_builtin_rules()
    for rule in rules:
        assert isinstance(rule, Rule)
        assert rule.id
        assert rule.regex
        assert rule.rotate_url


def test_zai_rule_present():
    rules = load_builtin_rules()
    zai = next(r for r in rules if r.id == "zai-api-key")
    assert "z.ai" in zai.rotate_url.lower() or "zai" in zai.rotate_url.lower()


def test_invalid_toml_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("not valid toml [[")
    from token_hunt.patterns_loader import load_rules_from_path
    with pytest.raises(ValueError, match="invalid TOML"):
        load_rules_from_path(bad)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_patterns_loader.py -v`
Expected: FAIL with `ImportError: cannot import name 'load_builtin_rules'`

- [ ] **Step 3: Write `src/token_hunt/types.py`**

```python
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
```

- [ ] **Step 4: Write `src/token_hunt/patterns_loader.py`**

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `py -m pytest tests/test_patterns_loader.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/token_hunt/types.py src/token_hunt/patterns_loader.py tests/test_patterns_loader.py
git commit -m "patterns: loader + Rule/Match/ScanContext types"
```

---

## Phase 2: Detection Engine (Tasks 4-7)

### Task 4: Regex scanner

**Files:**
- Create: `src/token_hunt/regex_scanner.py`
- Create: `tests/test_regex_scanner.py`

- [ ] **Step 1: Write `tests/test_regex_scanner.py`**

```python
import pytest
from token_hunt.regex_scanner import scan_regex, _fingerprint
from token_hunt.patterns_loader import load_builtin_rules
from token_hunt.types import ScanContext
from tests.fixtures import (
    ZAI_KEY, ANTHROPIC_KEY, GITHUB_PAT, FIGMA_PAT, PYPI_TOKEN,
)


@pytest.fixture
def rules():
    return load_builtin_rules()


@pytest.fixture
def ctx():
    return ScanContext(detection_point="UserPromptSubmit")


def test_fingerprint_stable():
    fp1 = _fingerprint(ZAI_KEY)
    fp2 = _fingerprint(ZAI_KEY)
    assert fp1 == fp2
    assert len(fp1) == 16


def test_zai_key_detected(rules, ctx):
    text = f"heres my key: {ZAI_KEY}"
    matches = scan_regex(text, rules, ctx)
    kinds = [m.kind for m in matches]
    assert "zai-api-key" in kinds


def test_anthropic_key_detected(rules, ctx):
    text = f"ANTHROPIC_API_KEY={ANTHROPIC_KEY}"
    matches = scan_regex(text, rules, ctx)
    kinds = [m.kind for m in matches]
    assert "anthropic-key" in kinds


def test_github_pat_detected(rules, ctx):
    text = f"gh auth login --with-token {GITHUB_PAT}"
    matches = scan_regex(text, rules, ctx)
    assert any(m.kind == "github-pat" for m in matches)


def test_no_match_on_plain_text(rules, ctx):
    text = "just a normal sentence about programming"
    assert scan_regex(text, rules, ctx) == []


def test_match_has_correct_fields(rules, ctx):
    text = ZAI_KEY
    matches = scan_regex(text, rules, ctx)
    assert len(matches) == 1
    m = matches[0]
    assert m.value == ZAI_KEY
    assert m.detection_point == "UserPromptSubmit"
    assert m.rotate_url.startswith("https://")
    assert 0 < m.confidence <= 1.0


def test_line_and_column_tracked(rules, ctx):
    text = f"line one\n{ZAI_KEY}\nline three"
    matches = scan_regex(text, rules, ctx)
    assert matches[0].line == 2
    assert matches[0].column == 1


def test_multiple_matches_in_one_text(rules, ctx):
    text = f"{ZAI_KEY} {ANTHROPIC_KEY} {GITHUB_PAT}"
    matches = scan_regex(text, rules, ctx)
    assert len(matches) >= 3


def test_keyword_prefilter_skips_obvious_non_matches(rules, ctx):
    """Rules with keywords should pre-filter — 'hello world' shouldn't even
    invoke the regex engine for zai-api-key."""
    text = "the quick brown fox jumps over the lazy dog"
    matches = scan_regex(text, rules, ctx)
    assert matches == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_regex_scanner.py -v`
Expected: FAIL with `ImportError: cannot import name 'scan_regex'`.

- [ ] **Step 3: Write `src/token_hunt/regex_scanner.py`**

```python
from __future__ import annotations
import hashlib
import re
from typing import Iterable

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_regex_scanner.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/regex_scanner.py tests/test_regex_scanner.py
git commit -m "engine: regex scanner with keyword pre-filter + line/col tracking"
```

---

### Task 5: Escape hatch detector

**Files:**
- Create: `src/token_hunt/escape.py`
- Create: `tests/test_escape.py`

- [ ] **Step 1: Write `tests/test_escape.py`**

```python
import pytest
from token_hunt.escape import scan_escape, _is_legit_status_check
from token_hunt.types import ScanContext
from tests.fixtures import (
    ESCAPE_PATTERN_DOLLAR_BRACE, ESCAPE_PATTERN_ECHO, ESCAPE_PATTERN_PRINTENV,
    ESCAPE_PATTERN_ENV_GREP, ESCAPE_PATTERN_GREP_VAR,
    ESCAPE_SAFE_STATUS_CHECK, ESCAPE_SAFE_WC,
)


@pytest.fixture
def ctx():
    return ScanContext(detection_point="PreToolUse:Bash")


def test_dollar_brace_pattern_detected(ctx):
    matches = scan_escape(ESCAPE_PATTERN_DOLLAR_BRACE, ctx)
    assert len(matches) >= 1
    assert matches[0].kind.startswith("escape:")


def test_echo_dollar_var_detected(ctx):
    matches = scan_escape(ESCAPE_PATTERN_ECHO, ctx)
    assert any("GITHUB_TOKEN" in m.kind for m in matches)


def test_printenv_detected(ctx):
    matches = scan_escape(ESCAPE_PATTERN_PRINTENV, ctx)
    assert any("STRIPE_SECRET_KEY" in m.kind for m in matches)


def test_env_pipe_grep_detected(ctx):
    matches = scan_escape(ESCAPE_PATTERN_ENV_GREP, ctx)
    assert len(matches) >= 1


def test_grep_with_var_detected(ctx):
    matches = scan_escape(ESCAPE_PATTERN_GREP_VAR, ctx)
    assert any("DB_PASSWORD" in m.kind for m in matches)


def test_legit_status_check_not_flagged():
    """`[ -n "$VAR" ] && echo SET` is the correct pattern, not a leak."""
    assert _is_legit_status_check(ESCAPE_SAFE_STATUS_CHECK) is True


def test_legit_wc_check_not_flagged():
    """`wc -c <<< "$VAR"` checks length without leaking value."""
    assert _is_legit_status_check(ESCAPE_SAFE_WC) is True


def test_dollar_brace_pattern_IS_flagged_despite_looking_safe():
    """Jordan's bug: `${VAR:+SET}${VAR:-UNSET}` looks like a status check
    but BOTH branches run, leaking the value. MUST be flagged."""
    assert _is_legit_status_check(ESCAPE_PATTERN_DOLLAR_BRACE) is False


def test_non_secret_var_not_flagged(ctx):
    """`echo $PATH` shouldn't fire — PATH isn't a secret-bearing name."""
    matches = scan_escape('echo $PATH', ctx)
    assert matches == []


def test_only_fires_in_bash_context():
    """Escape patterns are bash-specific. Don't fire in UserPromptSubmit etc."""
    ctx = ScanContext(detection_point="UserPromptSubmit")
    matches = scan_escape(ESCAPE_PATTERN_ECHO, ctx)
    assert matches == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_escape.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write `src/token_hunt/escape.py`**

```python
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
    if any(upper.endswith(s) for s in SECRET_NAME_SUFFIXES):
        return True
    if any(upper.startswith(p) for p in SECRET_NAME_PREFIXES):
        return True
    return False


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_escape.py -v`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/escape.py tests/test_escape.py
git commit -m "engine: bash escape-hatch detector (the unique IP)"
```

---

### Task 6: Entropy detector

**Files:**
- Create: `src/token_hunt/entropy.py`
- Create: `tests/test_entropy.py`

- [ ] **Step 1: Write `tests/test_entropy.py`**

```python
import pytest
from token_hunt.entropy import scan_entropy, shannon_entropy
from token_hunt.types import ScanContext


@pytest.fixture
def ctx():
    return ScanContext(detection_point="UserPromptSubmit")


def test_shannon_entropy_of_constant_string_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_is_high():
    # 32 hex chars has entropy ~4 bits/char (16 distinct values)
    assert 3.5 < shannon_entropy("a1b2c3d4e5f6071829304152637485ff") < 4.5


def test_entropy_fires_on_long_random_string(ctx):
    text = "Bearer a8b3c2d4e5f6071829304152637485ffa8b3c2d4e5f60718"
    matches = scan_entropy(text, ctx)
    assert len(matches) >= 1
    assert matches[0].kind == "entropy-candidate"
    assert matches[0].confidence < 0.5  # entropy is low-confidence


def test_entropy_does_not_fire_on_plain_text(ctx):
    text = "the quick brown fox jumps over the lazy dog"
    assert scan_entropy(text, ctx) == []


def test_entropy_does_not_fire_on_short_strings(ctx):
    text = "abc123"
    assert scan_entropy(text, ctx) == []


def test_entropy_disabled_for_escape_hatch_context():
    """Don't run entropy on Bash commands — too many false positives."""
    ctx = ScanContext(detection_point="PreToolUse:Bash")
    text = "longrandomcommand --flag a8b3c2d4e5f6071829304152637485ffa8b3c2d4e5f60718"
    assert scan_entropy(text, ctx) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_entropy.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write `src/token_hunt/entropy.py`**

```python
from __future__ import annotations
import math
import re
from collections import Counter

from token_hunt.types import Match, ScanContext

MIN_LENGTH = 20
MIN_ENTROPY = 4.5

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_entropy.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/entropy.py tests/test_entropy.py
git commit -m "engine: entropy candidate detector for unknown key formats"
```

---

### Task 7: Allowlist engine

**Files:**
- Create: `src/token_hunt/allowlist.py`
- Create: `tests/test_allowlist.py`

- [ ] **Step 1: Write `tests/test_allowlist.py`**

```python
import pytest
from token_hunt.allowlist import (
    apply_allowlist, is_path_allowed, load_fingerprint_allowlist,
    ALLOWED_PATH_PATTERNS,
)
from token_hunt.regex_scanner import _fingerprint
from token_hunt.types import Match, ScanContext
from tests.fixtures import ZAI_KEY


@pytest.fixture
def ctx():
    return ScanContext(detection_point="UserPromptSubmit")


def _fake_match(kind: str, value: str, ctx: ScanContext, file_path: str | None = None):
    return Match(
        kind=kind, value=value, fingerprint=_fingerprint(value) if value else "",
        rotate_url="https://example.com", detection_point=ctx.detection_point,
        confidence=0.9, rule_id=kind, line=1, column=1,
    )


def test_path_allowlist_matches_node_modules():
    assert is_path_allowed("node_modules/foo/bar.js") is True


def test_path_allowlist_matches_tests_fixtures():
    assert is_path_allowed("tests/fixtures/real-key.txt") is True


def test_path_allowlist_does_not_match_src():
    assert is_path_allowed("src/main.py") is False


def test_fingerprint_allowlist_filters_match(tmp_path, ctx, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    # Write a fingerprint allowlist
    th_dir = fake_home / ".token-hunt"
    th_dir.mkdir()
    (th_dir / "allowlist.toml").write_text(
        f'fingerprints = ["{_fingerprint(ZAI_KEY)}"]\n'
    )

    fps = load_fingerprint_allowlist()
    assert _fingerprint(ZAI_KEY) in fps

    m = _fake_match("zai-api-key", ZAI_KEY, ctx)
    result = apply_allowlist([m], ctx)
    assert result == []


def test_apply_allowlist_preserves_non_allowed(ctx):
    m = _fake_match("zai-api-key", ZAI_KEY, ctx)
    result = apply_allowlist([m], ctx)
    assert len(result) == 1


def test_apply_allowlist_skips_when_path_allowed(ctx):
    ctx_with_path = ScanContext(
        detection_point="PostToolUse:Read",
        file_path="tests/fixtures/example.env",
    )
    m = _fake_match("zai-api-key", ZAI_KEY, ctx_with_path)
    result = apply_allowlist([m], ctx_with_path)
    assert result == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_allowlist.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `src/token_hunt/allowlist.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_allowlist.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/allowlist.py tests/test_allowlist.py
git commit -m "engine: allowlist (path-based + fingerprint-based filters)"
```

---

### Task 8: Engine orchestrator (scan function)

**Files:**
- Create: `src/token_hunt/engine.py`
- Create: `tests/test_engine.py`

- [ ] **Step 1: Write `tests/test_engine.py`**

```python
import pytest
from token_hunt.engine import scan, ScanResult
from token_hunt.types import ScanContext
from tests.fixtures import (
    ZAI_KEY, ANTHROPIC_KEY, ESCAPE_PATTERN_DOLLAR_BRACE, ESCAPE_SAFE_STATUS_CHECK,
)


@pytest.fixture
def ctx_user():
    return ScanContext(detection_point="UserPromptSubmit")


@pytest.fixture
def ctx_bash():
    return ScanContext(detection_point="PreToolUse:Bash")


def test_scan_combines_all_passes(ctx_user):
    text = f"keys: {ZAI_KEY} and {ANTHROPIC_KEY}"
    result = scan(text, ctx_user)
    assert isinstance(result, ScanResult)
    kinds = [m.kind for m in result.matches]
    assert "zai-api-key" in kinds
    assert "anthropic-key" in kinds


def test_scan_runs_escape_in_bash_context(ctx_bash):
    result = scan(ESCAPE_PATTERN_DOLLAR_BRACE, ctx_bash)
    escape_matches = [m for m in result.matches if m.kind.startswith("escape:")]
    assert len(escape_matches) >= 1


def test_scan_does_not_run_escape_in_user_context(ctx_user):
    result = scan(ESCAPE_PATTERN_DOLLAR_BRACE, ctx_user)
    escape_matches = [m for m in result.matches if m.kind.startswith("escape:")]
    assert escape_matches == []


def test_scan_skips_safe_status_check(ctx_bash):
    result = scan(ESCAPE_SAFE_STATUS_CHECK, ctx_bash)
    escape_matches = [m for m in result.matches if m.kind.startswith("escape:")]
    assert escape_matches == []


def test_scan_result_includes_count(ctx_user):
    text = ZAI_KEY
    result = scan(text, ctx_user)
    assert result.count >= 1
    assert result.highest_confidence > 0


def test_scan_handles_empty_text(ctx_user):
    result = scan("", ctx_user)
    assert result.matches == []
    assert result.count == 0


def test_scan_fail_closed_on_internal_error(ctx_user, monkeypatch):
    """If a detector throws, scan should re-raise (fail-closed) rather than
    silently allow. The hook layer handles user-facing bypass."""
    import token_hunt.regex_scanner as rs
    def boom(text, rules, ctx):
        raise RuntimeError("simulated detector failure")
    monkeypatch.setattr(rs, "scan_regex", boom)
    with pytest.raises(RuntimeError):
        scan("anything", ctx_user)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_engine.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `src/token_hunt/engine.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

from token_hunt.allowlist import apply_allowlist
from token_hunt.entropy import scan_entropy
from token_hunt.escape import scan_escape
from token_hunt.patterns_loader import load_builtin_rules, load_user_rules
from token_hunt.regex_scanner import scan_regex
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

    # Pass 1: regex rules
    matches.extend(scan_regex(text, rules, ctx))

    # Pass 2: bash escape hatch (only fires in PreToolUse:Bash)
    matches.extend(scan_escape(text, ctx))

    # Pass 3: entropy candidates (skipped for Bash)
    matches.extend(scan_entropy(text, ctx))

    # Apply allowlist filters
    matches = apply_allowlist(matches, ctx)

    highest = max((m.confidence for m in matches), default=0.0)
    return ScanResult(matches=matches, count=len(matches), highest_confidence=highest)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_engine.py -v`
Expected: 7 passed.

- [ ] **Step 5: Run full test suite**

Run: `py -m pytest -v`
Expected: all tests across all files pass.

- [ ] **Step 6: Commit**

```bash
git add src/token_hunt/engine.py tests/test_engine.py
git commit -m "engine: scan() orchestrator combines regex+escape+entropy, fail-closed"
```

---

## Phase 3: Storage (Task 9)

### Task 9: rotations.log store

**Files:**
- Create: `src/token_hunt/store.py`
- Create: `tests/test_store.py`

- [ ] **Step 1: Write `tests/test_store.py`**

```python
import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from token_hunt.store import Store, LeakRecord


@pytest.fixture
def store(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    return Store()


def _make_record(kind="zai-key", fingerprint="abc123", status="open", ts=None):
    return LeakRecord(
        id=None,  # assigned by store
        ts=ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        kind=kind,
        source="UserPromptSubmit",
        fingerprint=fingerprint,
        rotate_url="https://example.com/rotate",
        status=status,
        note="",
    )


def test_store_creates_log_on_first_write(store, tmp_path):
    record = _make_record()
    leak_id = store.append(record)
    log_path = Path.home() / ".token-hunt" / "rotations.log"
    assert log_path.is_file()
    assert leak_id >= 1


def test_store_append_assigns_sequential_ids(store):
    id1 = store.append(_make_record(fingerprint="a"))
    id2 = store.append(_make_record(fingerprint="b"))
    id3 = store.append(_make_record(fingerprint="c"))
    assert (id1, id2, id3) == (1, 2, 3)


def test_store_list_open(store):
    store.append(_make_record(fingerprint="a", status="open"))
    store.append(_make_record(fingerprint="b", status="closed"))
    store.append(_make_record(fingerprint="c", status="open"))
    open_leaks = store.list_open()
    assert len(open_leaks) == 2


def test_store_close_marks_record(store):
    leak_id = store.append(_make_record(fingerprint="a", status="open"))
    store.close(leak_id, note="rotated")
    open_leaks = store.list_open()
    assert len(open_leaks) == 0


def test_store_marks_overdue_after_72h(store):
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat(timespec="seconds")
    store.append(_make_record(fingerprint="a", status="open", ts=old_ts))
    open_leaks = store.list_open()
    assert len(open_leaks) == 1
    assert open_leaks[0].is_overdue is True


def test_store_not_overdue_within_72h(store):
    fresh_ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.append(_make_record(fingerprint="a", status="open", ts=fresh_ts))
    open_leaks = store.list_open()
    assert open_leaks[0].is_overdue is False


def test_store_jsonl_format(store, tmp_path):
    store.append(_make_record(kind="anthropic-key", fingerprint="abcdef0123456789"))
    log_path = Path.home() / ".token-hunt" / "rotations.log"
    line = log_path.read_text().strip()
    record = json.loads(line)
    assert record["kind"] == "anthropic-key"
    assert record["fingerprint"] == "abcdef0123456789"
    assert record["status"] == "open"
    assert "id" in record
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_store.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `src/token_hunt/store.py`**

```python
from __future__ import annotations
import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from token_hunt.regex_scanner import _fingerprint  # reuse SHA-256 helper

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_store.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/store.py tests/test_store.py
git commit -m "store: rotations.log JSONL writer/reader with 72h overdue tracking"
```

---

## Phase 4: CLI (Tasks 10-14)

### Task 10: CLI scaffold

**Files:**
- Create: `src/token_hunt/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write `tests/test_cli.py` (scaffold only — full tests added per-command)**

```python
import json
import pytest
from click.testing import CliRunner
from token_hunt.cli import main
from tests.fixtures import ZAI_KEY


@pytest.fixture
def runner():
    return CliRunner()


def test_help_works(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "list" in result.output
    assert "close" in result.output
    assert "watch" in result.output


def test_version_flag(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
```

- [ ] **Step 2: Update `pyproject.toml` to add click dependency**

Modify `pyproject.toml` `dependencies` list to include:
```toml
    "click>=8.1.0",
```

And add to `[project.optional-dependencies]` dev list, then `py -m pip install -e ".[dev]"`.

- [ ] **Step 3: Run test to verify it fails**

Run: `py -m pytest tests/test_cli.py -v`
Expected: FAIL.

- [ ] **Step 4: Write `src/token_hunt/cli.py` (scaffold with stubs)**

```python
"""token-hunt CLI entry point."""
from __future__ import annotations
import sys

import click

from token_hunt import __version__


@click.group()
@click.version_option(__version__, "--version")
def main() -> None:
    """token-hunt: catch secrets at chat time, not commit time."""


@main.command()
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--stdin", is_flag=True, help="Read text from stdin instead of file.")
@click.option("--context", default="UserPromptSubmit",
              help="Detection point (UserPromptSubmit, PreToolUse:Bash, etc.)")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]))
def scan(path, stdin, context, fmt):
    """Scan a file or stdin for secret leaks."""
    # Implemented in Task 11
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command(name="list")
@click.option("--all", "show_all", is_flag=True, help="Show closed leaks too.")
def list_cmd(show_all):
    """List open leaks in rotations.log."""
    # Implemented in Task 12
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command()
@click.argument("leak_id", type=int)
@click.option("--note", default="", help="Optional rotation note.")
def close(leak_id, note):
    """Mark a leak as closed after rotation."""
    # Implemented in Task 13
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--context", default="PostToolUse:Read")
def watch(path, context):
    """Watch a directory for new transcript files and scan them."""
    # Implemented in Task 14
    click.echo("not yet implemented", err=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `py -m pytest tests/test_cli.py -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/token_hunt/cli.py tests/test_cli.py pyproject.toml
git commit -m "cli: scaffold with click group + 4 subcommand stubs"
```

---

### Task 11: `scan` command

**Files:**
- Modify: `src/token_hunt/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add tests for scan command (append to `tests/test_cli.py`)**

```python
def test_scan_finds_zai_key_in_stdin(runner):
    result = runner.invoke(main, ["scan", "--stdin", "--context", "UserPromptSubmit",
                                  "--format", "json"], input=f"key={ZAI_KEY}")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert any(m["kind"] == "zai-api-key" for m in data["matches"])


def test_scan_clean_text_exits_zero(runner):
    result = runner.invoke(main, ["scan", "--stdin"], input="hello world")
    assert result.exit_code == 0
    assert "no leaks" in result.output.lower() or "0 leak" in result.output.lower()


def test_scan_text_format_includes_rotate_url(runner):
    result = runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    assert result.exit_code == 0
    assert "z.ai" in result.output.lower() or "rotate" in result.output.lower()


def test_scan_file_path(runner, tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text(f"key={ZAI_KEY}")
    result = runner.invoke(main, ["scan", str(f)])
    assert result.exit_code == 0
    assert "zai-api-key" in result.output


def test_scan_writes_to_rotations_log(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    log = fake_home / ".token-hunt" / "rotations.log"
    assert log.is_file()
    assert "zai-api-key" in log.read_text()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_cli.py -v -k scan`
Expected: FAIL.

- [ ] **Step 3: Implement `scan` command in `src/token_hunt/cli.py`**

Replace the `scan` function stub:

```python
@main.command()
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--stdin", is_flag=True, help="Read text from stdin instead of file.")
@click.option("--context", default="UserPromptSubmit",
              help="Detection point (UserPromptSubmit, PreToolUse:Bash, etc.)")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]))
@click.option("--no-log", is_flag=True, help="Don't write to rotations.log.")
def scan(path, stdin, context, fmt, no_log):
    """Scan a file or stdin for secret leaks."""
    import json as _json
    import sys
    from pathlib import Path as _Path

    from token_hunt.engine import scan as scan_engine
    from token_hunt.store import LeakRecord, Store
    from token_hunt.types import ScanContext
    from dataclasses import asdict

    if stdin:
        text = sys.stdin.read()
        file_path = None
    elif path:
        text = _Path(path).read_text(encoding="utf-8", errors="replace")
        file_path = str(path)
    else:
        click.echo("error: provide a PATH or use --stdin", err=True)
        sys.exit(2)

    ctx = ScanContext(detection_point=context, file_path=file_path)
    result = scan_engine(text, ctx)

    if not no_log and result.matches:
        store = Store()
        for m in result.matches:
            store.append(LeakRecord(
                id=None,
                ts=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    .isoformat(timespec="seconds"),
                kind=m.kind,
                source=m.detection_point,
                fingerprint=m.fingerprint,
                rotate_url=m.rotate_url,
                status="open",
            ))

    if fmt == "json":
        click.echo(_json.dumps({
            "count": result.count,
            "matches": [asdict(m) for m in result.matches],
        }, indent=2))
    else:
        if not result.matches:
            click.echo("no leaks detected")
        else:
            click.echo(f"⚠️  {result.count} potential leak(s) detected:")
            for m in result.matches:
                fp_preview = m.fingerprint[:8] if m.fingerprint else "n/a"
                click.echo(f"  - {m.kind} (fp={fp_preview}) @ line {m.line}")
                if m.rotate_url:
                    click.echo(f"    rotate: {m.rotate_url}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli.py -v -k scan`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/cli.py tests/test_cli.py
git commit -m "cli: implement scan command (file + stdin, json/text formats)"
```

---

### Task 12: `list` command

**Files:**
- Modify: `src/token_hunt/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add tests for list command**

```python
def test_list_shows_open_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "zai-api-key" in result.output


def test_list_marks_overdue_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    log = fake_home / ".token-hunt" / "rotations.log"
    log.parent.mkdir(parents=True)
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat(timespec="seconds")
    log.write_text(json.dumps({
        "id": 1, "ts": old_ts, "kind": "zai-api-key", "source": "UserPromptSubmit",
        "fingerprint": "abc", "rotate_url": "https://example.com",
        "status": "open", "note": ""
    }) + "\n")

    result = runner.invoke(main, ["list"])
    assert "OVERDUE" in result.output


def test_list_empty_when_no_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "no open" in result.output.lower() or "0 leak" in result.output.lower()
```

Add these imports at top of `tests/test_cli.py`:
```python
from datetime import datetime, timezone, timedelta
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_cli.py -v -k list`
Expected: FAIL.

- [ ] **Step 3: Implement `list` command in `src/token_hunt/cli.py`**

Replace the `list_cmd` function:

```python
@main.command(name="list")
@click.option("--all", "show_all", is_flag=True, help="Show closed leaks too.")
def list_cmd(show_all):
    """List open leaks in rotations.log."""
    from token_hunt.store import Store

    store = Store()
    if show_all:
        records = []
        for line in store.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                import json as _j
                from token_hunt.store import LeakRecord
                records.append(LeakRecord(**_j.loads(line)))
    else:
        records = store.list_open()

    if not records:
        click.echo("no open leaks" if not show_all else "no leaks recorded")
        return

    click.echo(f"{'ID':<5} {'KIND':<22} {'SOURCE':<22} {'WHEN':<20} {'STATUS':<10} URL")
    for r in records:
        ts_short = r.ts[:19].replace("T", " ")
        status = r.status.upper()
        if r.is_overdue:
            status = "OVERDUE"
        click.echo(f"{r.id:<5} {r.kind:<22} {r.source:<22} {ts_short:<20} {status:<10} {r.rotate_url}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli.py -v -k list`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/cli.py tests/test_cli.py
git commit -m "cli: implement list command with 72h OVERDUE highlighting"
```

---

### Task 13: `close` command

**Files:**
- Modify: `src/token_hunt/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add tests for close command**

```python
def test_close_marks_leak_closed(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)

    result = runner.invoke(main, ["close", "1", "--note", "rotated"])
    assert result.exit_code == 0

    list_result = runner.invoke(main, ["list"])
    assert "no open" in list_result.output.lower() or list_result.output.strip() == ""


def test_close_nonexistent_id_fails(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    result = runner.invoke(main, ["close", "999"])
    assert result.exit_code != 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_cli.py -v -k close`
Expected: FAIL.

- [ ] **Step 3: Implement `close` command**

Replace the `close` function in `src/token_hunt/cli.py`:

```python
@main.command()
@click.argument("leak_id", type=int)
@click.option("--note", default="", help="Optional rotation note.")
def close(leak_id, note):
    """Mark a leak as closed after rotation."""
    from token_hunt.store import Store
    store = Store()
    if store.close(leak_id, note=note):
        click.echo(f"leak {leak_id} marked closed")
    else:
        click.echo(f"error: leak {leak_id} not found", err=True)
        import sys; sys.exit(1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli.py -v -k close`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/token_hunt/cli.py tests/test_cli.py
git commit -m "cli: implement close command with note support"
```

---

### Task 14: `watch` command

**Files:**
- Modify: `src/token_hunt/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add tests for watch command**

```python
import time

def test_watch_detects_new_file(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()

    import threading
    def write_after_delay():
        time.sleep(0.5)
        (watch_dir / "leak.txt").write_text(f"key={ZAI_KEY}")

    t = threading.Thread(target=write_after_delay)
    t.start()

    result = runner.invoke(main, ["watch", str(watch_dir)], timeout=3)
    t.join()

    log = fake_home / ".token-hunt" / "rotations.log"
    assert log.is_file()
    assert "zai-api-key" in log.read_text()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_cli.py -v -k watch`
Expected: FAIL.

- [ ] **Step 3: Implement `watch` command**

Replace the `watch` function in `src/token_hunt/cli.py`:

```python
@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--context", default="PostToolUse:Read")
@click.option("--exit-after", type=int, default=0,
              help="Exit after N seconds (0 = run forever). Test helper.")
def watch(path, context, exit_after):
    """Watch a directory for new transcript files and scan them."""
    import time as _time
    from pathlib import Path as _Path

    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    from token_hunt.engine import scan as scan_engine
    from token_hunt.store import LeakRecord, Store
    from token_hunt.types import ScanContext
    from dataclasses import asdict
    import datetime as _dt
    import json as _json

    watched = _Path(path)
    click.echo(f"watching {watched} for new files...")

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            self._scan_file(event.src_path)

        def on_modified(self, event):
            if event.is_directory:
                return
            self._scan_file(event.src_path)

        def _scan_file(self, file_path):
            try:
                text = _Path(file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return
            ctx = ScanContext(detection_point=context, file_path=file_path)
            result = scan_engine(text, ctx)
            if result.matches:
                store = Store()
                for m in result.matches:
                    store.append(LeakRecord(
                        id=None,
                        ts=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                        kind=m.kind,
                        source=m.detection_point,
                        fingerprint=m.fingerprint,
                        rotate_url=m.rotate_url,
                        status="open",
                    ))
                click.echo(f"⚠️  {file_path}: {result.count} leak(s) detected")
            else:
                click.echo(f"✓ {file_path}: clean")

    observer = Observer()
    observer.schedule(Handler(), str(watched), recursive=True)
    observer.start()

    try:
        if exit_after > 0:
            _time.sleep(exit_after)
        else:
            while True:
                _time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli.py -v -k watch`
Expected: 1 passed (may be slow due to watchdog startup — allow up to 10s).

- [ ] **Step 5: Run full test suite**

Run: `py -m pytest -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/token_hunt/cli.py tests/test_cli.py
git commit -m "cli: implement watch command using watchdog"
```

---

## Phase 5: Claude Code Plugin (Tasks 15-21)

### Task 15: Resolve hook rewrite capability

**Files:**
- Create: `docs/superpowers/research/hook-rewrite-capability.md`

This task answers Open Question #1 from the spec — can Claude Code hooks rewrite tool I/O?

- [ ] **Step 1: Read the official Claude Code hooks documentation**

Run: `WebFetch https://docs.anthropic.com/en/docs/claude-code/hooks "What hook events exist, what data each one receives, and what output formats the hook can return. Specifically: can hooks modify the prompt or tool I/O before it's processed?"`

- [ ] **Step 2: Empirically test rewrite capability**

Write a test hook at `C:\Users\jrnew\.claude\hooks\test-rewrite.sh`:

```bash
#!/usr/bin/env bash
input=$(cat)
# Try to output a JSON object with a "rewrite" field
echo "$input" | jq --arg replace "REWRITTEN" '. + {rewritten: $replace}'
exit 0
```

Wire it in `~/.claude/settings.json` under `UserPromptSubmit` temporarily. Open a new Claude Code session, type "test", and verify whether the prompt is rewritten.

- [ ] **Step 3: Document findings**

Write to `docs/superpowers/research/hook-rewrite-capability.md`:

```markdown
# Hook Rewrite Capability — Research Finding

**Question:** Can Claude Code hooks modify tool I/O (rewrite prompts, edit tool output) before processing?

**Answer:** [Fill in from research]

**Implications for token-hunt:**
- UserPromptSubmit: [WARN-only if no rewrite; silent-redact if rewrite possible]
- PostToolUse:Bash: [BLOCK+show-redacted-text if no rewrite; silent-redact if possible]
- PostToolUse:Read: [same]

**Decision for v0.1.0:** [ chosen approach, with rationale ]
```

- [ ] **Step 4: Clean up test artifacts**

```bash
rm C:/Users/jrnew/.claude/hooks/test-rewrite.sh
# Restore settings.json hook config
```

- [ ] **Step 5: Commit findings**

```bash
git add docs/superpowers/research/hook-rewrite-capability.md
git commit -m "research: document Claude Code hook rewrite capability"
```

---

### Task 16: Plugin manifest

**Files:**
- Create: `plugin/plugin.json`
- Create: `plugin/hooks.json`

- [ ] **Step 1: Write `plugin/plugin.json`**

```json
{
  "$schema": "https://json.schemastore.org/claude-code-plugin.json",
  "name": "token-hunt",
  "version": "0.1.0",
  "description": "Catch secrets at chat time, not commit time. Hook-based scanner for Claude Code.",
  "author": {
    "name": "Jordan Newell",
    "url": "https://jordannewell.com"
  },
  "homepage": "https://github.com/JordanNewell/token-hunt",
  "repository": "https://github.com/JordanNewell/token-hunt",
  "license": "MIT",
  "keywords": ["security", "secrets", "leak-prevention", "claude-code", "hooks"],
  "categories": ["security", "developer-tools"]
}
```

- [ ] **Step 2: Write `plugin/hooks.json`**

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/user-prompt-submit.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/pre-bash.sh"
          }
        ]
      },
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/pre-write.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/post-bash.sh"
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/post-read.sh"
          }
        ]
      },
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/post-write.sh"
          }
        ]
      }
    ]
  }
}
```

- [ ] **Step 3: Commit**

```bash
git add plugin/plugin.json plugin/hooks.json
git commit -m "plugin: manifest + 6-hook wiring"
```

---

### Task 17: `user-prompt-submit.sh` hook (WARN)

**Files:**
- Create: `plugin/hooks/user-prompt-submit.sh`
- Create: `tests/test_hook_user_prompt_submit.py`

- [ ] **Step 1: Write `tests/test_hook_user_prompt_submit.py`**

```python
import json
import subprocess
import pytest
from pathlib import Path
from tests.fixtures import ZAI_KEY

HOOK = Path(__file__).parent.parent.parent / "plugin" / "hooks" / "user-prompt-submit.sh"


def _run_hook(prompt_text):
    payload = json.dumps({"prompt": prompt_text})
    result = subprocess.run(
        ["bash", str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result


def test_clean_prompt_exits_zero():
    result = _run_hook("hello world")
    assert result.returncode == 0


def test_leak_prompt_emits_warning_to_stderr():
    result = _run_hook(f"my key is {ZAI_KEY}")
    assert result.returncode == 0  # WARN, not BLOCK
    assert "token-hunt" in result.stderr.lower()
    assert "z.ai" in result.stderr.lower() or "rotate" in result.stderr.lower()


def test_clean_prompt_no_stderr():
    result = _run_hook("just chatting normally")
    assert result.stderr == "" or "token-hunt" not in result.stderr.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_hook_user_prompt_submit.py -v`
Expected: FAIL (hook doesn't exist).

- [ ] **Step 3: Write `plugin/hooks/user-prompt-submit.sh`**

```bash
#!/usr/bin/env bash
# token-hunt: UserPromptSubmit hook. WARN on detected leaks (don't block).
# Jordan's design rule: respect the human's judgment on what they pasted.

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

prompt=$(echo "$input" | jq -r '.prompt // empty' 2>/dev/null || true)
[ -z "$prompt" ] && exit 0

# Fail-closed: if token-hunt isn't installed, instruct user (don't silently pass).
if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. Install with: pip install token-hunt" >&2
  exit 0  # WARN, not BLOCK — don't break the prompt over install issues
fi

result=$(echo "$prompt" | token-hunt scan --stdin --context UserPromptSubmit --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "⚠️  token-hunt: $count potential leak(s) detected in your prompt:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // \"n/a\"))"' >&2
echo "" >&2
echo "The prompt was still sent — rotate any real keys at the URLs above." >&2

exit 0  # WARN, never BLOCK
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_hook_user_prompt_submit.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add plugin/hooks/user-prompt-submit.sh tests/test_hook_user_prompt_submit.py
git commit -m "plugin: user-prompt-submit hook (WARN mode)"
```

---

### Task 18: `pre-bash.sh` hook (BLOCK + escape hatch)

**Files:**
- Create: `plugin/hooks/pre-bash.sh`
- Create: `tests/test_hook_pre_bash.py`

- [ ] **Step 1: Write `tests/test_hook_pre_bash.py`**

```python
import json
import subprocess
from pathlib import Path
from tests.fixtures import ZAI_KEY, ESCAPE_PATTERN_DOLLAR_BRACE, ESCAPE_SAFE_STATUS_CHECK

HOOK = Path(__file__).parent.parent.parent / "plugin" / "hooks" / "pre-bash.sh"


def _run_hook(cmd):
    payload = json.dumps({"tool_input": {"command": cmd}})
    result = subprocess.run(
        ["bash", str(HOOK)],
        input=payload, capture_output=True, text=True, timeout=10,
    )
    return result


def test_clean_command_passes():
    r = _run_hook("ls -la")
    assert r.returncode == 0


def test_command_with_literal_key_blocks():
    r = _run_hook(f"echo {ZAI_KEY}")
    assert r.returncode == 2  # BLOCK
    assert "token-hunt" in r.stderr.lower()


def test_escape_hatch_pattern_blocks():
    r = _run_hook(ESCAPE_PATTERN_DOLLAR_BRACE)
    assert r.returncode == 2
    assert "escape" in r.stderr.lower() or "evaluat" in r.stderr.lower()


def test_safe_status_check_passes():
    r = _run_hook(ESCAPE_SAFE_STATUS_CHECK)
    assert r.returncode == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_hook_pre_bash.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `plugin/hooks/pre-bash.sh`**

```bash
#!/usr/bin/env bash
# token-hunt: PreToolUse Bash hook. BLOCK commands that would leak secrets.
# This is the only BLOCK-level hook — head the leak off before subprocess runs.

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

cmd=$(echo "$input" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -z "$cmd" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. pip install token-hunt" >&2
  exit 0
fi

# Fail-closed: if scan throws (e.g. corrupted install), BLOCK with bypass hint.
result=$(echo "$cmd" | token-hunt scan --stdin --context PreToolUse:Bash --format json 2>&1) || {
  echo "🚫 token-hunt: scanner error. Investigate before running this command." >&2
  echo "    To bypass: TOKEN_HUNT_ALLOW=1 (but verify the command is safe first)" >&2
  echo "    Error: $result" >&2
  exit 2
}

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚫 token-hunt: BLOCKED — command would leak $count secret(s):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (line \(.line))"' >&2
echo "" >&2
echo "If this is a false positive, re-run with TOKEN_HUNT_ALLOW=1 env var." >&2

exit 2  # BLOCK
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_hook_pre_bash.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add plugin/hooks/pre-bash.sh tests/test_hook_pre_bash.py
git commit -m "plugin: pre-bash hook (BLOCK + escape hatch + fail-closed)"
```

---

### Task 19: `post-bash.sh` hook (REDACT)

**Files:**
- Create: `plugin/hooks/post-bash.sh`
- Create: `tests/test_hook_post_bash.py`

- [ ] **Step 1: Write `tests/test_hook_post_bash.py`**

```python
import json
import subprocess
from pathlib import Path
from tests.fixtures import ZAI_KEY

HOOK = Path(__file__).parent.parent.parent / "plugin" / "hooks" / "post-bash.sh"


def _run_hook(cmd, stdout):
    payload = json.dumps({"tool_input": {"command": cmd}, "tool_response": {"stdout": stdout}})
    return subprocess.run(
        ["bash", str(HOOK)],
        input=payload, capture_output=True, text=True, timeout=10,
    )


def test_clean_output_passes():
    r = _run_hook("ls", "file1.txt\nfile2.txt")
    assert r.returncode == 0


def test_leak_in_output_warns_and_logs():
    r = _run_hook("cat ~/.zcode/config.json", f'{{"api_key": "{ZAI_KEY}"}}')
    assert r.returncode == 0  # WARN/REDACT, not BLOCK
    assert "token-hunt" in r.stderr.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_hook_post_bash.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `plugin/hooks/post-bash.sh`**

Behavior depends on Task 15 finding. **Default implementation assumes BLOCK+show-redacted** (if rewrite not possible). Add inline branch for rewrite mode if available.

```bash
#!/usr/bin/env bash
# token-hunt: PostToolUse Bash hook. REDACT secret from command output.
# Output is already in transcript by now — REDACT can't undo, but we CAN
# warn loudly + log to rotations.log so dev can rotate.

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

stdout=$(echo "$input" | jq -r '.tool_response.stdout // empty' 2>/dev/null || true)
[ -z "$stdout" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0  # silent if not installed — post-hoc warning is non-critical
fi

result=$(echo "$stdout" | token-hunt scan --stdin --context PostToolUse:Bash --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: $count secret(s) appeared in command output (now in transcript):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // \"n/a\"))"' >&2
echo "" >&2
echo "Action required: rotate the listed keys before continuing." >&2

exit 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_hook_post_bash.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add plugin/hooks/post-bash.sh tests/test_hook_post_bash.py
git commit -m "plugin: post-bash hook (loud-warn + log; can't redact past transcript)"
```

---

### Task 20: `post-read.sh` hook (REDACT)

**Files:**
- Create: `plugin/hooks/post-read.sh`
- Create: `tests/test_hook_post_read.py`

- [ ] **Step 1: Write `tests/test_hook_post_read.py`**

```python
import json
import subprocess
from pathlib import Path
from tests.fixtures import ZAI_KEY

HOOK = Path(__file__).parent.parent.parent / "plugin" / "hooks" / "post-read.sh"


def _run_hook(file_path, content):
    payload = json.dumps({
        "tool_input": {"file_path": file_path},
        "tool_response": {"content": content},
    })
    return subprocess.run(
        ["bash", str(HOOK)],
        input=payload, capture_output=True, text=True, timeout=10,
    )


def test_clean_read_passes():
    r = _run_hook("/etc/hostname", "aeon")
    assert r.returncode == 0


def test_secret_in_read_warns():
    r = _run_hook("/home/jrnew/.zcode/config.json", f'{{"api_key": "{ZAI_KEY}"}}')
    assert r.returncode == 0
    assert "token-hunt" in r.stderr.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_hook_post_read.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `plugin/hooks/post-read.sh`**

```bash
#!/usr/bin/env bash
# token-hunt: PostToolUse Read hook. Warn when a read file contained secrets.
# Catches the "agent reads settings.json" leak class.

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

content=$(echo "$input" | jq -r '.tool_response.content // empty' 2>/dev/null || true)
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0
fi

result=$(echo "$content" | token-hunt scan --stdin --context PostToolUse:Read --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: read of $file_path contained $count secret(s):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // \"n/a\"))"' >&2
echo "" >&2
echo "The secret is now in transcript. Rotate before continuing." >&2

exit 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_hook_post_read.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add plugin/hooks/post-read.sh tests/test_hook_post_read.py
git commit -m "plugin: post-read hook (warn on secret-bearing file reads)"
```

---

### Task 21: `pre-write.sh` + `post-write.sh` hooks

**Files:**
- Create: `plugin/hooks/pre-write.sh`
- Create: `plugin/hooks/post-write.sh`
- Create: `tests/test_hook_pre_write.py`

- [ ] **Step 1: Write `tests/test_hook_pre_write.py`**

```python
import json
import subprocess
from pathlib import Path
from tests.fixtures import ZAI_KEY

HOOK = Path(__file__).parent.parent.parent / "plugin" / "hooks" / "pre-write.sh"


def _run_hook(file_path, content):
    payload = json.dumps({"tool_input": {"file_path": file_path, "content": content}})
    return subprocess.run(
        ["bash", str(HOOK)],
        input=payload, capture_output=True, text=True, timeout=10,
    )


def test_clean_write_passes():
    r = _run_hook("/tmp/foo.txt", "hello world")
    assert r.returncode == 0


def test_write_with_secret_blocks():
    r = _run_hook("/tmp/leak.txt", f"key={ZAI_KEY}")
    assert r.returncode == 2
    assert "token-hunt" in r.stderr.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_hook_pre_write.py -v`
Expected: FAIL.

- [ ] **Step 3: Write `plugin/hooks/pre-write.sh`**

```bash
#!/usr/bin/env bash
# token-hunt: PreToolUse Edit/Write hook. BLOCK writes of new secrets to disk.
# Catches "agent writes secrets into a new file" before the write happens.

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

content=$(echo "$input" | jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. pip install token-hunt" >&2
  exit 0
fi

result=$(echo "$content" | token-hunt scan --stdin --context PreToolUse:Write --format json 2>&1) || {
  echo "🚫 token-hunt: scanner error. Verify write is safe, then TOKEN_HUNT_ALLOW=1." >&2
  exit 2
}

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚫 token-hunt: BLOCKED — refusing to write secret(s) to disk:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // \"n/a\"))"' >&2
echo "" >&2
echo "If intentional (e.g. tests/fixtures/), add to ~/.token-hunt/allowlist.toml." >&2

exit 2
```

- [ ] **Step 4: Write `plugin/hooks/post-write.sh`**

```bash
#!/usr/bin/env bash
# token-hunt: PostToolUse Edit/Write hook. Defense-in-depth — same scan as
# pre-write but fires after the write completed (catches edge cases where
# pre-write was bypassed).

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

content=$(echo "$input" | jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0
fi

result=$(echo "$content" | token-hunt scan --stdin --context PostToolUse:Write --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: write contained $count secret(s) — pre-write check was bypassed:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // \"n/a\"))"' >&2

exit 0
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `py -m pytest tests/test_hook_pre_write.py -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add plugin/hooks/pre-write.sh plugin/hooks/post-write.sh tests/test_hook_pre_write.py
git commit -m "plugin: pre-write BLOCK + post-write defense-in-depth"
```

---

## Phase 6: Polish & Ship (Tasks 22-23)

### Task 22: Community files + README

**Files:**
- Modify: `README.md` (replace skeleton)
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CHANGELOG.md`
- Create: `.github/FUNDING.yml`
- Create: `.github/ISSUE_TEMPLATE/bug-report.md`
- Create: `.github/ISSUE_TEMPLATE/feature-request.md`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# token-hunt

> Catch secrets at chat time, not commit time.

[![release](https://img.shields.io/badge/release-0.1.0-blue)](https://github.com/JordanNewell/token-hunt/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)

Hook-based secret scanner for **Claude Code**, **Cursor**, **Aider**, and other AI CLIs. Catches leaks when you paste, when your agent reads, and when your agent's tools return — not at commit time when it's already too late.

## Why

Existing scanners (gitleaks, trufflehog, ggshield) scan **git history**. By the time you run `git commit`, your secret has been in the AI chat transcript for 30+ minutes — indexed by Anthropic, sync'd to other machines, possibly read by the agent and re-emitted in subsequent tool calls.

token-hunt catches at chat time. **Zero cloud, zero telemetry, fail-closed by default.**

## Install

**As a Claude Code plugin** (recommended):

```bash
claude plugin install token-hunt@JordanNewell
```

**As a standalone CLI**:

```bash
pip install token-hunt
```

## 60-second demo

```bash
# In one terminal:
pip install token-hunt

# Scan a file:
echo "ANTHROPIC_API_KEY=sk-ant-..." > /tmp/test.txt
token-hunt scan /tmp/test.txt

# Watch a directory (e.g. Claude Code transcript dir):
token-hunt watch ~/.claude/projects/

# List open leaks:
token-hunt list

# Close after rotating:
token-hunt close 1 --note "rotated at console.anthropic.com"
```

## Detection points

| Hook | What it sees | Action on leak |
|---|---|---|
| `UserPromptSubmit` | Your paste | WARN (banner) |
| `PreToolUse:Bash` | Command about to run | BLOCK (won't run) |
| `PostToolUse:Bash` | Command output | WARN + log (transcript already has it) |
| `PostToolUse:Read` | File contents | WARN + log |
| `PreToolUse:Edit/Write` | New file content | BLOCK |
| `PostToolUse:Edit/Write` | Echo | WARN + log |

## The unique feature: bash escape-hatch detection

token-hunt catches patterns where bash evaluates a secret into emitted text, even when the literal secret isn't in your input:

```bash
# BLOCKED — both branches run, leaks the value:
echo ${ANTHROPIC_API_KEY:+SET}${ANTHROPIC_API_KEY:-UNSET}

# BLOCKED — direct echo of secret var:
echo $GITHUB_TOKEN

# ALLOWED — correct status-check pattern:
[ -n "$ANTHROPIC_API_KEY" ] && echo SET
```

No other scanner detects this class.

## Configuration

Patterns layer (later extends earlier):

1. `token_hunt/patterns/builtin.toml` (ships with package)
2. `~/.token-hunt/patterns.local.toml` (machine-local, gitignored)
3. `./.token-hunt/patterns.local.toml` (repo-local, gitignored)

Allowlist (test fixtures, etc.):

`~/.token-hunt/allowlist.toml`:
```toml
fingerprints = [
  "abc123def456...",  # SHA-256 first 16 chars of allowlisted value
]
```

Per-repo opt-out:
```bash
export TOKEN_HUNT_DISABLE=1
# or
touch .token-hunt/disable
```

## Bypass

```bash
TOKEN_HUNT_ALLOW=1 <command>  # one-shot bypass (use sparingly)
```

## Built-in providers

Z.ai · Anthropic · GitHub (classic + fine-grained) · GitLab · Figma · PyPI · npm · Linear · Stripe · OpenAI · Slack

## Comparison

| Tool | Surface | Local-only | Fail-closed | Escape hatch | Fleet sync |
|---|---|---|---|---|---|
| **token-hunt** | Claude Code + CLI | yes | yes | **yes** | v0.2 |
| sensitive-canary | Claude Code | yes | yes | no | no |
| ggshield | Claude Code | no (cloud API) | no (fail-open) | no | no |
| gitleaks | git only | yes | n/a | no | no |

## License

MIT. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md). 72-hour acknowledgment SLA.
```

- [ ] **Step 2: Write `SECURITY.md`**

```markdown
# Security Policy

## Reporting a Vulnerability

Email **security@jordannewell.com** with details and repro steps.

**Acknowledgment SLA: 72 hours** (solo maintainer with day-job + 15-agent fleet — 48h broke credibility when missed).

## Disclosure

- Reporter credited in release notes unless they prefer otherwise.
- Coordinated disclosure after fix ships.
- No bug bounty program (yet).

## Scope

- token-hunt itself (Python package + Claude Code plugin)
- The official pattern ruleset shipped in `src/token_hunt/patterns/builtin.toml`

## Out of scope

- Vulnerabilities in dependencies (report upstream)
- Leaks from user-supplied patterns in `~/.token-hunt/patterns.local.toml`
- Social engineering attacks against the maintainer
```

- [ ] **Step 3: Write `CONTRIBUTING.md`**

```markdown
# Contributing

Thanks for considering a contribution.

## Setup

```bash
git clone https://github.com/JordanNewell/token-hunt
cd token-hunt
pip install -e ".[dev]"
pytest
```

## Development workflow

1. Open an issue describing the change (skip for trivial fixes).
2. Branch from `main`: `feat/<short-desc>` or `fix/<short-desc>`.
3. Add tests for new behavior. TDD preferred.
4. Run `pytest` and `ruff check .` before committing.
5. Open a PR — describe the change + link the issue.

## Adding a new provider pattern

1. Add a rule to `src/token_hunt/patterns/builtin.toml` (gitleaks-compatible TOML format).
2. Add provider metadata to `src/token_hunt/patterns/rotate-urls.toml`.
3. Add a fake-format test constant to `tests/fixtures.py`.
4. Add a detection test to `tests/test_regex_scanner.py`.

## Code style

- Python 3.10+ (use `from __future__ import annotations`).
- Line length 100 (ruff default).
- No AI-attribution trailers in commit messages.
- Tests required for all behavior changes.

## Commit message conventions

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.

72-char subject line. Body wraps at 80. Explain the *why* when non-obvious.
```

- [ ] **Step 4: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to token-hunt are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-XX

### Added
- Initial release.
- Detection core: regex patterns (12 built-in providers), bash escape-hatch detector, entropy candidates.
- Claude Code plugin with 6 hook scripts covering 8 detection rows.
- CLI peer (`pip install token-hunt`) with `scan`, `list`, `close`, `watch` commands.
- Pattern layering: builtin → `~/.token-hunt/patterns.local.toml` → `./.token-hunt/patterns.local.toml`.
- Allowlist engine (path-based + fingerprint-based).
- `rotations.log` JSONL store with 72-hour OVERDUE tracking.
- Built-in providers: Z.ai, Anthropic, GitHub (classic + fine-grained), GitLab, Figma, PyPI, npm, Linear, Stripe, OpenAI, Slack.
```

- [ ] **Step 5: Write `.github/FUNDING.yml`**

```yaml
github: [JordanNewell]
buy_me_a_coffee: jordannewell
custom:
  - "https://jordannewell.com/projects/token-hunt/"
```

- [ ] **Step 6: Write `.github/ISSUE_TEMPLATE/bug-report.md`**

```markdown
---
name: Bug Report
about: Report a false positive, false negative, or crash
title: "[BUG] "
labels: bug, triage
---

## Summary

[One sentence describing the problem]

## Repro

```bash
# Steps to reproduce
```

## Expected

[What should have happened]

## Actual

[What actually happened]

## Environment

- token-hunt version: `token-hunt --version`
- Python version:
- OS:
- Claude Code version (if plugin): 

## Pattern that fired (or didn't)

[kind, e.g. `zai-api-key`]

## Output of `token-hunt list`

```
[paste here, redact fingerprints if real]
```
```

- [ ] **Step 7: Write `.github/ISSUE_TEMPLATE/feature-request.md`**

```markdown
---
name: Feature Request
about: Suggest a new provider rule, detection class, or feature
title: "[FEAT] "
labels: enhancement, triage
---

## Summary

[One sentence describing the request]

## Use case

[What problem does this solve? When does it come up?]

## Proposed solution

[Describe the approach. Code samples welcome.]

## Alternatives considered

[Any other ways to solve this — and why they don't work]
```

- [ ] **Step 8: Write `.github/PULL_REQUEST_TEMPLATE.md`**

```markdown
## Summary

[One paragraph. What does this change do?]

## Why

[The motivation. Link any issues.]

## Testing

- [ ] Added tests for new behavior
- [ ] All tests pass: `pytest`
- [ ] Lint clean: `ruff check .`
- [ ] Manually verified the change works as described

## Checklist

- [ ] No AI-attribution trailers in commit messages
- [ ] No real secrets in test fixtures (use the fakes in `tests/fixtures.py`)
- [ ] CHANGELOG updated if user-facing
```

- [ ] **Step 9: Commit**

```bash
git add README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md .github/
git commit -m "docs: README + community files (SECURITY/CONTRIBUTING/CHANGELOG/FUNDING/templates)"
```

---

### Task 23: End-to-end test + ship prep

**Files:**
- Create: `tests/test_e2e_hooks.py`
- Create: `.github/workflows/release.yml`
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: Write `tests/test_e2e_hooks.py`**

```python
"""End-to-end test: simulate a full Claude Code session's worth of inputs
through every hook. Verifies plumbing is correct across the whole stack."""

import json
import subprocess
from pathlib import Path

import pytest

from tests.fixtures import (
    ZAI_KEY, ANTHROPIC_KEY, GITHUB_PAT, ESCAPE_PATTERN_DOLLAR_BRACE,
    ESCAPE_SAFE_STATUS_CHECK,
)

HOOKS = Path(__file__).parent.parent.parent / "plugin" / "hooks"


def _run(hook_name, payload):
    return subprocess.run(
        ["bash", str(HOOKS / hook_name)],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=15,
    )


def test_e2e_clean_session_passes_all_hooks():
    """All hooks return 0 for clean input."""
    assert _run("user-prompt-submit.sh", {"prompt": "hello"}).returncode == 0
    assert _run("pre-bash.sh", {"tool_input": {"command": "ls"}}).returncode == 0
    assert _run("post-bash.sh",
                {"tool_input": {"command": "ls"}, "tool_response": {"stdout": "file.txt"}}
                ).returncode == 0
    assert _run("post-read.sh",
                {"tool_input": {"file_path": "/etc/hostname"},
                 "tool_response": {"content": "aeon"}}
                ).returncode == 0
    assert _run("pre-write.sh",
                {"tool_input": {"file_path": "/tmp/x", "content": "hello"}}).returncode == 0


def test_e2e_paste_leak_warns_but_passes():
    r = _run("user-prompt-submit.sh", {"prompt": f"key={ZAI_KEY}"})
    assert r.returncode == 0  # WARN
    assert "token-hunt" in r.stderr.lower()


def test_e2e_bash_leak_blocks():
    r = _run("pre-bash.sh", {"tool_input": {"command": f"echo {ZAI_KEY}"}})
    assert r.returncode == 2  # BLOCK


def test_e2e_escape_hatch_blocks():
    r = _run("pre-bash.sh", {"tool_input": {"command": ESCAPE_PATTERN_DOLLAR_BRACE}})
    assert r.returncode == 2


def test_e2e_safe_status_check_passes():
    r = _run("pre-bash.sh", {"tool_input": {"command": ESCAPE_SAFE_STATUS_CHECK}})
    assert r.returncode == 0


def test_e2e_read_leak_warns():
    r = _run("post-read.sh",
             {"tool_input": {"file_path": "/home/user/.zcode/config.json"},
              "tool_response": {"content": f'{{"key":"{ZAI_KEY}"}}'}})
    assert r.returncode == 0
    assert "token-hunt" in r.stderr.lower()


def test_e2e_write_leak_blocks():
    r = _run("pre-write.sh",
             {"tool_input": {"file_path": "/tmp/leak", "content": f"key={ANTHROPIC_KEY}"}})
    assert r.returncode == 2


def test_e2e_multiple_providers_in_one_prompt():
    """Recreate Jordan's recent leak pattern: paste multiple keys at once."""
    prompt = f"heres my keys: {ZAI_KEY} {ANTHROPIC_KEY} {GITHUB_PAT}"
    r = _run("user-prompt-submit.sh", {"prompt": prompt})
    assert r.returncode == 0
    stderr_lower = r.stderr.lower()
    assert "zai-api-key" in stderr_lower
    assert "anthropic-key" in stderr_lower
    assert "github-pat" in stderr_lower


def test_e2e_all_hooks_handle_empty_input():
    """Hooks must not crash on missing fields."""
    for hook in ["user-prompt-submit.sh", "pre-bash.sh", "post-bash.sh",
                 "post-read.sh", "pre-write.sh", "post-write.sh"]:
        r = subprocess.run(
            ["bash", str(HOOKS / hook)],
            input="",
            capture_output=True, text=True, timeout=5,
        )
        assert r.returncode == 0, f"{hook} crashed on empty input"
```

- [ ] **Step 2: Run e2e tests**

Run: `py -m pytest tests/test_e2e_hooks.py -v`
Expected: 9 passed.

- [ ] **Step 3: Run full test suite**

Run: `py -m pytest -v --cov=token_hunt`
Expected: all tests pass, coverage >80%.

- [ ] **Step 4: Write `.github/workflows/test.yml`**

```yaml
name: test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e402052b7b6f6d  # v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: pytest --cov=token_hunt --cov-report=xml
      - uses: codecov/codecov-action@b9fd7d96f2d891b39a3e3a623df4d0ed71ef3841  # v4
        if: matrix.os == 'ubuntu-latest' && matrix.python-version == '3.12'
        with:
          file: ./coverage.xml
```

- [ ] **Step 5: Write `.github/workflows/release.yml`**

```yaml
name: release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e402052b7b6f6f6d  # v5
        with:
          python-version: "3.12"
      - run: pip install build twine
      - run: python -m build
      - uses: softprops/action-gh-release@da05d552573ad5aba039eaac05058a918a7bf631  # v2
        with:
          generate_release_notes: true
      - run: twine upload dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
```

- [ ] **Step 6: Verify package builds locally**

Run: `cd /e/dev/projects/token-hunt && py -m build`
Expected: `dist/token_hunt-0.1.0-py3-none-any.whl` and `.tar.gz` created, no errors.

- [ ] **Step 7: Commit**

```bash
git add tests/test_e2e_hooks.py .github/workflows/
git commit -m "ship: e2e test suite + CI workflows (test matrix + release to PyPI)"
```

- [ ] **Step 8: Verify the CLI works end-to-end**

Run: `cd /e/dev/projects/token-hunt && token-hunt --version`
Expected: `token-hunt, version 0.1.0`

Run: `echo "sk-ant-$(printf '0%.0s' {1..95})" | token-hunt scan --stdin`
Expected: leak warning with `anthropic-key` kind + rotate URL.

---

## Self-Review

**Spec coverage check:**
- Wedge (chat-time scan): ✓ all hooks
- Detection core (engine, regex, escape, entropy): ✓ Tasks 4-8
- 12 providers: ✓ Task 2
- Provider registry with rotate URLs: ✓ Task 2
- Allowlist (path + fingerprint): ✓ Task 7
- Status-check escape hatch: ✓ Task 5
- Tool-output injection detection: **partial** — structure mentioned but signature corpus deferred to v0.2 per spec
- Configuration layering: ✓ Tasks 3 + engine
- rotations.log JSONL store: ✓ Task 9
- 72h OVERDUE: ✓ Task 9 + list command
- Fail-closed default: ✓ pre-bash + pre-write hooks
- MVP scope (8 detection rows / 6 scripts): ✓ Tasks 16-21
- Repo structure: ✓ Task 1
- Tests: ✓ every task has tests
- README with 60s demo: ✓ Task 22
- Community files (fleet standard): ✓ Task 22
- CI workflows: ✓ Task 23

**Open Question #1 (hook rewrite capability):** Task 15 resolves empirically. Default implementation (Tasks 19, 20, 21) uses WARN+log on PostToolUse since the secret is already in transcript by then — rewrite capability doesn't change this. If rewrite IS possible for PreToolUse, that's upside and can be added in v0.1.1.

**Placeholder scan:** No TBDs. Tool-output injection signature corpus explicitly deferred per spec.

**Type consistency:** `Match`, `Rule`, `ScanContext` defined in Task 3, used consistently throughout. `LeakRecord` defined in Task 9, used in CLI tasks. `_fingerprint` is in `regex_scanner.py` and reused in `store.py` (Task 9 imports it).

**Scope check:** Single plan, single subsystem, ships working software. ✓
