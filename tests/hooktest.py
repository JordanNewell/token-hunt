"""Shared helpers for hook tests. Extracted from test_hook_user_prompt_submit.py
after Task 17 identified three Windows-portability issues that recur across
every hook test (Tasks 18-21)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def find_bash() -> str:
    """Prefer Git Bash on Windows (WSL bash can't see Windows .exe CLIs)."""
    for candidate in ("bash.exe", "bash"):
        path = shutil.which(candidate)
        if path:
            return path
    return "bash"


def run_hook(script_relative_path: str, payload: dict, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a plugin hook script with the given JSON payload.

    Handles three Windows/Git-Bash portability issues:
    - bash.exe preferred over WSL bash (Windows .exe CLIs not visible to WSL)
    - Relative path + cwd=REPO_ROOT (absolute Windows paths mangled by MSYS)
    - encoding=utf-8 (Python defaults to cp1252 on Windows, corrupts UTF-8)
    """
    return subprocess.run(
        [find_bash(), script_relative_path],
        input=json.dumps(payload), check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=str(REPO_ROOT),
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )
