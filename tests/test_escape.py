import pytest

from tests.fixtures import (
    ESCAPE_PATTERN_DOLLAR_BRACE,
    ESCAPE_PATTERN_ECHO,
    ESCAPE_PATTERN_ENV_GREP,
    ESCAPE_PATTERN_GREP_VAR,
    ESCAPE_PATTERN_PRINTENV,
    ESCAPE_SAFE_STATUS_CHECK,
    ESCAPE_SAFE_WC,
)
from token_hunt.escape import _is_legit_status_check, scan_escape
from token_hunt.types import ScanContext


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
