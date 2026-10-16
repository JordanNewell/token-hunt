import pytest

from tests.fixtures import (
    ANTHROPIC_KEY,
    GITHUB_PAT,
    ZAI_KEY,
)
from token_hunt.patterns_loader import load_builtin_rules
from token_hunt.regex_scanner import _fingerprint, scan_regex
from token_hunt.types import ScanContext


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
