from tests.fixtures import ZAI_KEY
from tests.hooktest import run_hook

HOOK = "plugin/hooks/user-prompt-submit.sh"


def _run_hook(prompt_text):
    return run_hook(HOOK, {"prompt": prompt_text})


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
