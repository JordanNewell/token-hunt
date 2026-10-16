import pytest

from tests.fixtures import (
    ANTHROPIC_KEY,
    ESCAPE_PATTERN_DOLLAR_BRACE,
    ESCAPE_SAFE_STATUS_CHECK,
    ZAI_KEY,
)
from token_hunt.engine import ScanResult, scan
from token_hunt.types import ScanContext


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
