"""End-to-end test: simulate a full Claude Code session's worth of inputs
through every hook. Verifies plumbing is correct across the whole stack."""

import subprocess
from pathlib import Path


from tests.fixtures import (
    ZAI_KEY, ANTHROPIC_KEY, GITHUB_PAT, ESCAPE_PATTERN_DOLLAR_BRACE,
    ESCAPE_SAFE_STATUS_CHECK,
)
from tests.hooktest import run_hook


def test_e2e_clean_session_passes_all_hooks():
    """All hooks return 0 for clean input."""
    assert run_hook("plugin/hooks/user-prompt-submit.sh", {"prompt": "hello"}).returncode == 0
    assert run_hook("plugin/hooks/pre-bash.sh", {"tool_input": {"command": "ls"}}).returncode == 0
    assert run_hook("plugin/hooks/post-bash.sh",
                    {"tool_input": {"command": "ls"}, "tool_response": {"stdout": "file.txt"}}
                    ).returncode == 0
    assert run_hook("plugin/hooks/post-read.sh",
                    {"tool_input": {"file_path": "/etc/hostname"},
                     "tool_response": {"content": "aeon"}}
                    ).returncode == 0
    assert run_hook("plugin/hooks/pre-write.sh",
                    {"tool_input": {"file_path": "/tmp/x", "content": "hello"}}).returncode == 0


def test_e2e_paste_leak_warns_but_passes():
    r = run_hook("plugin/hooks/user-prompt-submit.sh", {"prompt": f"key={ZAI_KEY}"})
    assert r.returncode == 0  # WARN
    assert "token-hunt" in r.stderr.lower()


def test_e2e_bash_leak_blocks():
    r = run_hook("plugin/hooks/pre-bash.sh", {"tool_input": {"command": f"echo {ZAI_KEY}"}})
    assert r.returncode == 2  # BLOCK


def test_e2e_escape_hatch_blocks():
    r = run_hook("plugin/hooks/pre-bash.sh", {"tool_input": {"command": ESCAPE_PATTERN_DOLLAR_BRACE}})
    assert r.returncode == 2


def test_e2e_safe_status_check_passes():
    r = run_hook("plugin/hooks/pre-bash.sh", {"tool_input": {"command": ESCAPE_SAFE_STATUS_CHECK}})
    assert r.returncode == 0


def test_e2e_read_leak_warns():
    r = run_hook("plugin/hooks/post-read.sh",
                 {"tool_input": {"file_path": "/home/user/.zcode/config.json"},
                  "tool_response": {"content": f'{{"key":"{ZAI_KEY}"}}'}})
    assert r.returncode == 0
    assert "token-hunt" in r.stderr.lower()


def test_e2e_write_leak_blocks():
    r = run_hook("plugin/hooks/pre-write.sh",
                 {"tool_input": {"file_path": "/tmp/leak", "content": f"key={ANTHROPIC_KEY}"}})
    assert r.returncode == 2


def test_e2e_multiple_providers_in_one_prompt():
    """Recreate Jordan's recent leak pattern: paste multiple keys at once."""
    prompt = f"heres my keys: {ZAI_KEY} {ANTHROPIC_KEY} {GITHUB_PAT}"
    r = run_hook("plugin/hooks/user-prompt-submit.sh", {"prompt": prompt})
    assert r.returncode == 0
    stderr_lower = r.stderr.lower()
    assert "zai-api-key" in stderr_lower
    assert "anthropic-key" in stderr_lower
    assert "github-pat" in stderr_lower


def test_e2e_all_hooks_handle_empty_input():
    """Hooks must not crash on missing fields."""
    hooks = [
        "plugin/hooks/user-prompt-submit.sh",
        "plugin/hooks/pre-bash.sh",
        "plugin/hooks/post-bash.sh",
        "plugin/hooks/post-read.sh",
        "plugin/hooks/pre-write.sh",
        "plugin/hooks/post-write.sh",
    ]
    import os
    import shutil
    for hook in hooks:
        # Empty payload — call subprocess directly to send empty stdin
        bash_exe = shutil.which("bash.exe") or shutil.which("bash") or "bash"
        r = subprocess.run(
            [bash_exe, hook],
            input="",
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=5,
            cwd=str(Path(__file__).parent.parent),
            env={**os.environ, "MSYS_NO_PATHCONV": "1"},
        )
        assert r.returncode == 0, f"{hook} crashed on empty input (exit {r.returncode}, stderr: {r.stderr})"
