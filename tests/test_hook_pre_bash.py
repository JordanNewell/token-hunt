from tests.fixtures import ESCAPE_PATTERN_DOLLAR_BRACE, ESCAPE_SAFE_STATUS_CHECK, ZAI_KEY
from tests.hooktest import run_hook

HOOK = "plugin/hooks/pre-bash.sh"


def _run_hook(cmd):
    return run_hook(HOOK, {"tool_input": {"command": cmd}})


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
