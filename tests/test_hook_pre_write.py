from tests.fixtures import ZAI_KEY
from tests.hooktest import run_hook

HOOK = "plugin/hooks/pre-write.sh"


def _run_hook(file_path, content):
    return run_hook(HOOK, {"tool_input": {"file_path": file_path, "content": content}})


def test_clean_write_passes():
    r = _run_hook("/tmp/foo.txt", "hello world")
    assert r.returncode == 0


def test_write_with_secret_blocks():
    r = _run_hook("/tmp/leak.txt", f"key={ZAI_KEY}")
    assert r.returncode == 2
    assert "token-hunt" in r.stderr.lower()
