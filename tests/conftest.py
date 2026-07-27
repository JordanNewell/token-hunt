import pytest


@pytest.fixture
def tmp_token_hunt_home(tmp_path, monkeypatch):
    """Redirect ~/.token-hunt/ to a tmp dir for isolated tests."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    return fake_home / ".token-hunt"
