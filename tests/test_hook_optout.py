"""Test the TOKEN_HUNT_DISABLE opt-out. Verified after final code review
flagged that README documented the env var but no hook implemented it."""
import os

import pytest

from tests.fixtures import ZAI_KEY
from tests.hooktest import run_hook

HOOKS = [
    "plugin/hooks/user-prompt-submit.sh",
    "plugin/hooks/pre-bash.sh",
    "plugin/hooks/post-bash.sh",
    "plugin/hooks/post-read.sh",
    "plugin/hooks/pre-write.sh",
    "plugin/hooks/post-write.sh",
]


@pytest.mark.parametrize("hook", HOOKS)
def test_token_hunt_disable_skips_hook(hook, monkeypatch):
    """TOKEN_HUNT_DISABLE=1 must cause every hook to exit 0 immediately,
    even when the input would normally trigger a leak."""
    monkeypatch.setenv("TOKEN_HUNT_DISABLE", "1")

    # Use a payload that would normally trigger each hook
    if hook.endswith("user-prompt-submit.sh"):
        payload = {"prompt": f"key={ZAI_KEY}"}
    elif hook.endswith("pre-bash.sh"):
        payload = {"tool_input": {"command": f"echo {ZAI_KEY}"}}
    elif hook.endswith("post-bash.sh"):
        payload = {"tool_input": {"command": "cat"}, "tool_response": {"stdout": ZAI_KEY}}
    elif hook.endswith("post-read.sh"):
        payload = {"tool_input": {"file_path": "/x"}, "tool_response": {"content": ZAI_KEY}}
    elif hook.endswith("pre-write.sh"):
        payload = {"tool_input": {"file_path": "/tmp/x", "content": f"key={ZAI_KEY}"}}
    else:  # post-write
        payload = {"tool_input": {"file_path": "/tmp/x", "content": f"key={ZAI_KEY}"}}

    result = run_hook(hook, payload)
    assert result.returncode == 0, f"{hook} should exit 0 when TOKEN_HUNT_DISABLE=1"
    # And should NOT emit any token-hunt warning
    assert "token-hunt" not in result.stderr.lower()
