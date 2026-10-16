"""Per-rule smoke tests for the builtin provider ruleset.

Each new rule gets a fake sample key (shape-correct, not a real credential)
that MUST match, plus a near-miss that MUST NOT. Samples were verified against
provider docs / gitleaks / trufflehog on 2026-10-15 — see builtin.toml header.
"""
import pytest

from token_hunt.patterns_loader import load_builtin_rules
from token_hunt.regex_scanner import scan_regex
from token_hunt.types import ScanContext

# (rule_id, line that must match, line that must NOT match)
CASES = [
    ("openrouter-key",
     "OPENROUTER_API_KEY=sk-or-v1-" + "a1b2c3d4" * 8,
     "OPENROUTER_API_KEY=sk-or-v1-" + "a1b2c3d" * 8),  # 56 hex — too short
    ("groq-key",
     "GROQ_API_KEY=gsk_" + "K7mN2pQrStUvWxYz0123456789abcdefghijABCD",
     "GROQ_API_KEY=gsk_short"),
    ("together-key",
     "TOGETHER_API_KEY=tgp_v1_" + "Ab09_-CdEf" * 4 + "GhIj",
     "TOGETHER_API_KEY=tgp_v2_" + "Ab09_-CdEf" * 4),
    ("fireworks-key",
     "FIREWORKS_API_KEY=fw_AbCdEf0123456789ghij",
     "FIREWORKS_API_KEY=fw_short"),
    ("xai-key",
     "XAI_API_KEY=xai-" + "0123456789" * 8,
     "XAI_API_KEY=xai-abc"),
    ("perplexity-key",
     "PERPLEXITY_API_KEY=pplx-" + "0123456789abcdef" * 3,
     "PERPLEXITY_API_KEY=pplx_abc"),
    ("huggingface-key",
     "HF_TOKEN=hf_" + "0123456789abcdef0123456789abcdefABCD",
     "HF_TOKEN=hf_short"),
    ("cerebras-key",
     "CEREBRAS_API_KEY=csk_" + "0123456789abcdefghijklmnopqrstuvwxyz" * 2,
     "CEREBRAS_API_KEY=csk_ABC"),  # uppercase body — cerebras bodies are lowercase
    ("replicate-key",
     "REPLICATE_API_TOKEN=r8_" + "0123456789abcdef0123456789abcdefghijk",
     "REPLICATE_API_TOKEN=r8_short"),
    ("vercel-gateway-key",
     "VERCEL_AI_GATEWAY=vck_0123456789abcdefghijklmnop",
     "VERCEL_AI_GATEWAY=vck__"),  # body too short
    ("nvidia-nim-key",
     "NVIDIA_API_KEY=nvapi-0123456789abcdefghijklmnop",
     "NVIDIA_API_KEY=nvapi-"),
    ("chutes-key",
     "CHUTES_API_KEY=cpk_0123456789abcdefghijklmnop",
     "CHUTES_API_KEY=cpk__"),
    ("requesty-key",
     "REQUESTY_API_KEY=rqsty-sk-0123456789abcdefgh",
     "REQUESTY_API_KEY=sk-0123456789abcdefgh"),
    ("novita-key",
     "novita NOVITA_API_KEY=sk_0123456789abcdefghijklmnop",
     "sk_0123456789abcdefghijklmnop"),  # no keyword — must not fire
    ("upstage-key",
     "upstage UPSTAGE_API_KEY=up_0123456789abcdefghijklmnop",
     "up_0123456789abcdefghijklmnop"),  # bare up_ without keyword — no fire
    ("baseten-key",
     "BASETEN_API_KEY=b10_abcd1234.0123456789abcdef0123456789abcdef",
     "BASETEN_API_KEY=b10_abcd1234-0123456789abcdef0123456789abcdef"),  # no dot
    ("qianfan-key",
     "QIANFAN_API_KEY=bce-v3/ALTAK-0123456789/0123456789abcdef",
     "QIANFAN_API_KEY=bce-v3/ALTAK_/"),
    ("fal-key",
     "FAL_KEY for fal: 0123abcd-12ab-34cd-56ef-0123456789ab:0123456789abcdef0123456789abcdef",
     "0123abcd-12ab-34cd-56ef-0123456789ab"),  # bare uuid, no secret half
    ("dashscope-key",
     "DASHSCOPE_API_KEY=sk-ws-0123456789abcdefghijklmnop",
     "DASHSCOPE_API_KEY=sk_0123456789abcdefghijklmnop"),
    ("moonshot-kimi-key",
     "KIMI_API_KEY=sk-kimi-0123456789abcdefghijklmn",
     "KIMI_API_KEY=sk_0123456789abcdefghijklmn"),
    ("mistral-key",
     "mistral MISTRAL_API_KEY=0123456789abcdef0123456789abcdef",
     "random_text = 0123456789abcdef0123456789abcdef"),  # no keyword — no fire
    ("cohere-key",
     "cohere COHERE_API_KEY=0123456789abcdef0123456789abcdef01234567",
     "random_text = 0123456789abcdef0123456789abcdef01234567"),
    ("scaleway-key",
     "scaleway SCW_ACCESS_KEY=0123abcd-12ab-34cd-56ef-0123456789ab",
     "id = 0123abcd-12ab-34cd-56ef-0123456789ab"),  # no keyword — no fire
    ("generic-sk-key",
     "DEEPSEEK_API_KEY=sk-q7w8e9r1t2y3u4i5o6p1a2s3d4f5g6hz",
     "sk-q7w8e9r1t2y3u4i5o6p1a2s3d4f5g6hzXYZ"),  # trailing caps — lookaround blocks
    ("generic-jwt",
     "MINIMAX token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
     "not.a.jwt"),
    ("sambanova-key",
     "sambanova key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("nebius-key",
     "nebius key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("ai21-key",
     "ai21 key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("ovh-key",
     "ovh key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("friendliai-key",
     "friendli key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("gmi-key",
     "gmi key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("crusoe-key",
     "crusoe key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("featherless-key",
     "featherless key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("deepinfra-key",
     "deepinfra key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("inference-net-key",
     "inference.net key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
    ("byteplus-key",
     "byteplus key = 0123456789abcdefghijklmnopqrstuv",
     "key = 0123456789abcdefghijklmnopqrstuv"),  # no keyword - no fire,
]


@pytest.fixture(scope="module")
def rules():
    return load_builtin_rules()


@pytest.fixture
def ctx():
    return ScanContext(detection_point="test", cwd="/tmp")


@pytest.mark.parametrize("rule_id,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_provider_rule_positive_and_negative(rules, ctx, rule_id, positive, negative):
    pos_matches = [m for m in scan_regex(positive, rules, ctx) if m.rule_id == rule_id]
    assert pos_matches, f"{rule_id} did not match its positive sample"

    neg_matches = [m for m in scan_regex(negative, rules, ctx) if m.rule_id == rule_id]
    assert not neg_matches, f"{rule_id} matched its negative sample"


def test_openai_rule_not_shadowed_by_generic_sk(rules, ctx):
    """The tightened OpenAI rule (T3BlbkFJ marker) and the generic sk-32 rule
    must not double-fire on the same OpenAI key."""
    openai_key = "sk-proj-abc123XYZ_" * 4 + "T3BlbkFJ" + "abc123XYZ_" * 4
    matches = scan_regex(f"key = {openai_key}", rules, ctx)
    ids = {m.rule_id for m in matches}
    assert "openai-key" in ids
    assert "generic-sk-key" not in ids


def test_all_new_rules_have_unique_ids(rules):
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
