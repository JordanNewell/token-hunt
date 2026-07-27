from tests.fixtures import ZAI_KEY
from tests.hooktest import run_hook

HOOK = "plugin/hooks/post-read.sh"


def _run_hook(file_path, content):
    return run_hook(HOOK, {
        "tool_input": {"file_path": file_path},
        "tool_response": {"content": content},
    })


def test_clean_read_passes():
    r = _run_hook("/etc/hostname", "aeon")
    assert r.returncode == 0


def test_secret_in_read_warns():
    r = _run_hook("/home/jrnew/.zcode/config.json", f'{{"api_key": "{ZAI_KEY}"}}')
    assert r.returncode == 0
    assert "token-hunt" in r.stderr.lower()
