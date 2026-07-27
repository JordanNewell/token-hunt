from tests.fixtures import ZAI_KEY
from tests.hooktest import run_hook

HOOK = "plugin/hooks/post-bash.sh"


def _run_hook(cmd, stdout):
    return run_hook(HOOK, {
        "tool_input": {"command": cmd},
        "tool_response": {"stdout": stdout},
    })


def test_clean_output_passes():
    r = _run_hook("ls", "file1.txt\nfile2.txt")
    assert r.returncode == 0


def test_leak_in_output_warns_and_logs():
    r = _run_hook("cat ~/.zcode/config.json", f'{{"api_key": "{ZAI_KEY}"}}')
    assert r.returncode == 0  # WARN/REDACT, not BLOCK
    assert "token-hunt" in r.stderr.lower()
