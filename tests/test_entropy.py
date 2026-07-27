import pytest
from token_hunt.entropy import scan_entropy, shannon_entropy
from token_hunt.types import ScanContext


@pytest.fixture
def ctx():
    return ScanContext(detection_point="UserPromptSubmit")


def test_shannon_entropy_of_constant_string_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_is_high():
    # 32 hex chars has entropy ~4 bits/char (16 distinct values)
    assert 3.5 < shannon_entropy("a1b3c2d4e5f6071829304152637485ff") < 4.5


def test_entropy_fires_on_long_random_string(ctx):
    text = "Bearer a8b3c2d4e5f6071829304152637485ffa8b3c2d4e5f60718"
    matches = scan_entropy(text, ctx)
    assert len(matches) >= 1
    assert matches[0].kind == "entropy-candidate"
    assert matches[0].confidence < 0.5  # entropy is low-confidence


def test_entropy_does_not_fire_on_plain_text(ctx):
    text = "the quick brown fox jumps over the lazy dog"
    assert scan_entropy(text, ctx) == []


def test_entropy_does_not_fire_on_short_strings(ctx):
    text = "abc123"
    assert scan_entropy(text, ctx) == []


def test_entropy_disabled_for_escape_hatch_context():
    """Don't run entropy on Bash commands — too many false positives."""
    ctx = ScanContext(detection_point="PreToolUse:Bash")
    text = "longrandomcommand --flag a8b3c2d4e5f6071829304152637485ffa8b3c2d4e5f60718"
    assert scan_entropy(text, ctx) == []
