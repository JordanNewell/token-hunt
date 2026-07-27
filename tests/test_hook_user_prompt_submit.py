import json
import os
import shutil
import subprocess
from pathlib import Path
from tests.fixtures import ZAI_KEY

REPO_ROOT = Path(__file__).parent.parent
# Relative path + cwd so Git Bash on Windows resolves the path correctly
# (absolute Windows paths get mangled by MSYS when passed as argv).
HOOK = "plugin/hooks/user-prompt-submit.sh"


def _find_bash():
    """Prefer Git Bash on Windows (WSL bash can't see Windows .exe CLIs)."""
    for candidate in ("bash.exe", "bash"):
        path = shutil.which(candidate)
        if path:
            return path
    return "bash"


def _run_hook(prompt_text):
    payload = json.dumps({"prompt": prompt_text})
    result = subprocess.run(
        [_find_bash(), HOOK],
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        cwd=str(REPO_ROOT),
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
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
