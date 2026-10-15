import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from token_hunt.store import Store, LeakRecord


@pytest.fixture
def store(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    return Store()


def _make_record(kind="zai-key", fingerprint="abc123", status="open", ts=None):
    return LeakRecord(
        id=None,  # assigned by store
        ts=ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        kind=kind,
        source="UserPromptSubmit",
        fingerprint=fingerprint,
        rotate_url="https://example.com/rotate",
        status=status,
        note="",
    )


def test_store_creates_log_on_first_write(store, tmp_path):
    record = _make_record()
    leak_id = store.append(record)
    log_path = Path.home() / ".token-hunt" / "rotations.log"
    assert log_path.is_file()
    assert leak_id >= 1


def test_store_append_assigns_sequential_ids(store):
    id1 = store.append(_make_record(fingerprint="a"))
    id2 = store.append(_make_record(fingerprint="b"))
    id3 = store.append(_make_record(fingerprint="c"))
    assert (id1, id2, id3) == (1, 2, 3)


def test_store_list_open(store):
    store.append(_make_record(fingerprint="a", status="open"))
    store.append(_make_record(fingerprint="b", status="closed"))
    store.append(_make_record(fingerprint="c", status="open"))
    open_leaks = store.list_open()
    assert len(open_leaks) == 2


def test_store_close_marks_record(store):
    leak_id = store.append(_make_record(fingerprint="a", status="open"))
    store.close(leak_id, note="rotated")
    open_leaks = store.list_open()
    assert len(open_leaks) == 0


def test_store_marks_overdue_after_72h(store):
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat(timespec="seconds")
    store.append(_make_record(fingerprint="a", status="open", ts=old_ts))
    open_leaks = store.list_open()
    assert len(open_leaks) == 1
    assert open_leaks[0].is_overdue is True


def test_store_not_overdue_within_72h(store):
    fresh_ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.append(_make_record(fingerprint="a", status="open", ts=fresh_ts))
    open_leaks = store.list_open()
    assert open_leaks[0].is_overdue is False


def test_store_jsonl_format(store, tmp_path):
    store.append(_make_record(kind="anthropic-key", fingerprint="abcdef0123456789"))
    log_path = Path.home() / ".token-hunt" / "rotations.log"
    line = log_path.read_text().strip()
    record = json.loads(line)
    assert record["kind"] == "anthropic-key"
    assert record["fingerprint"] == "abcdef0123456789"
    assert record["status"] == "open"
    assert "id" in record
