import json
from datetime import datetime, timezone, timedelta

import pytest
from click.testing import CliRunner
from token_hunt.cli import main
from tests.fixtures import ZAI_KEY


@pytest.fixture
def runner():
    return CliRunner()


def test_help_works(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "list" in result.output
    assert "close" in result.output
    assert "watch" in result.output


def test_version_flag(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_scan_finds_zai_key_in_stdin(runner):
    result = runner.invoke(main, ["scan", "--stdin", "--context", "UserPromptSubmit",
                                  "--format", "json"], input=f"key={ZAI_KEY}")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert any(m["kind"] == "zai-api-key" for m in data["matches"])


def test_scan_clean_text_exits_zero(runner):
    result = runner.invoke(main, ["scan", "--stdin"], input="hello world")
    assert result.exit_code == 0
    assert "no leaks" in result.output.lower() or "0 leak" in result.output.lower()


def test_scan_text_format_includes_rotate_url(runner):
    result = runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    assert result.exit_code == 0
    assert "z.ai" in result.output.lower() or "rotate" in result.output.lower()


def test_scan_file_path(runner, tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text(f"key={ZAI_KEY}")
    result = runner.invoke(main, ["scan", str(f)])
    assert result.exit_code == 0
    assert "zai-api-key" in result.output


def test_scan_writes_to_rotations_log(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    log = fake_home / ".token-hunt" / "rotations.log"
    assert log.is_file()
    assert "zai-api-key" in log.read_text()


def test_list_shows_open_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "zai-api-key" in result.output


def test_list_marks_overdue_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    log = fake_home / ".token-hunt" / "rotations.log"
    log.parent.mkdir(parents=True)
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat(timespec="seconds")
    log.write_text(json.dumps({
        "id": 1, "ts": old_ts, "kind": "zai-api-key", "source": "UserPromptSubmit",
        "fingerprint": "abc", "rotate_url": "https://example.com",
        "status": "open", "note": ""
    }) + "\n")

    result = runner.invoke(main, ["list"])
    assert "OVERDUE" in result.output


def test_list_empty_when_no_leaks(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "no open" in result.output.lower() or "0 leak" in result.output.lower()


def test_close_marks_leak_closed(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    runner.invoke(main, ["scan", "--stdin"], input=ZAI_KEY)

    result = runner.invoke(main, ["close", "1", "--note", "rotated"])
    assert result.exit_code == 0

    list_result = runner.invoke(main, ["list"])
    assert "no open" in list_result.output.lower() or list_result.output.strip() == ""


def test_close_nonexistent_id_fails(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    result = runner.invoke(main, ["close", "999"])
    assert result.exit_code != 0


import time

def test_watch_detects_new_file(runner, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()

    import threading
    def write_after_delay():
        time.sleep(0.5)
        (watch_dir / "leak.txt").write_text(f"key={ZAI_KEY}")

    t = threading.Thread(target=write_after_delay)
    t.start()

    result = runner.invoke(main, ["watch", str(watch_dir), "--exit-after", "3"])
    t.join()

    log = fake_home / ".token-hunt" / "rotations.log"
    assert log.is_file()
    assert "zai-api-key" in log.read_text()
