import pytest
from click.testing import CliRunner
from token_hunt.cli import main


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
