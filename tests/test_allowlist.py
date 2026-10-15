import pytest
from token_hunt.allowlist import (
    apply_allowlist, is_path_allowed, load_fingerprint_allowlist,
)
from token_hunt.regex_scanner import _fingerprint
from token_hunt.types import Match, ScanContext
from tests.fixtures import ZAI_KEY


@pytest.fixture
def ctx():
    return ScanContext(detection_point="UserPromptSubmit")


def _fake_match(kind: str, value: str, ctx: ScanContext, file_path: str | None = None):
    return Match(
        kind=kind, value=value, fingerprint=_fingerprint(value) if value else "",
        rotate_url="https://example.com", detection_point=ctx.detection_point,
        confidence=0.9, rule_id=kind, line=1, column=1,
    )


def test_path_allowlist_matches_node_modules():
    assert is_path_allowed("node_modules/foo/bar.js") is True


def test_path_allowlist_matches_tests_fixtures():
    assert is_path_allowed("tests/fixtures/real-key.txt") is True


def test_path_allowlist_does_not_match_src():
    assert is_path_allowed("src/main.py") is False


def test_fingerprint_allowlist_filters_match(tmp_path, ctx, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    # Write a fingerprint allowlist
    th_dir = fake_home / ".token-hunt"
    th_dir.mkdir()
    (th_dir / "allowlist.toml").write_text(
        f'fingerprints = ["{_fingerprint(ZAI_KEY)}"]\n'
    )

    fps = load_fingerprint_allowlist()
    assert _fingerprint(ZAI_KEY) in fps

    m = _fake_match("zai-api-key", ZAI_KEY, ctx)
    result = apply_allowlist([m], ctx)
    assert result == []


def test_apply_allowlist_preserves_non_allowed(ctx):
    m = _fake_match("zai-api-key", ZAI_KEY, ctx)
    result = apply_allowlist([m], ctx)
    assert len(result) == 1


def test_apply_allowlist_skips_when_path_allowed(ctx):
    ctx_with_path = ScanContext(
        detection_point="PostToolUse:Read",
        file_path="tests/fixtures/example.env",
    )
    m = _fake_match("zai-api-key", ZAI_KEY, ctx_with_path)
    result = apply_allowlist([m], ctx_with_path)
    assert result == []
