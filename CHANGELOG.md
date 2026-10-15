# Changelog

All notable changes to token-hunt are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Provider coverage expanded 12 → 37 rules for LLM-inference parity with the 53 providers Curtis ships: OpenRouter, Groq, Together, Fireworks, xAI, Perplexity, Hugging Face, Cerebras, Replicate, Vercel AI Gateway, NVIDIA NIM, Chutes, Requesty, Novita, Upstage, Baseten, Baidu Qianfan, fal.ai, Alibaba DashScope, Moonshot Kimi, Mistral, Cohere, Scaleway.
- Generic fallback rules: unattributed `sk-` 32-char key (DeepSeek / StepFun / Moonshot / SiliconFlow / Poe / Qwen shape) and generic JWT (MiniMax / DeepInfra / Crusoe).
- OpenAI rule tightened to the T3BlbkFJ marker shape — no longer double-fires with the generic `sk-` rule.
- Prefixless shapes (Mistral, Cohere, Scaleway) and generic-prefix shapes (Novita, Upstage) are keyword-gated: the provider name must appear in the scanned text before the regex is tried.
- Providers with no publicly documented key format get no regex rule — they fall back to the entropy pass. Shapes are provider-documented or multi-scanner-observed only; no guessed regexes.

### Planned for v0.1.1
- Silent redaction via `hookSpecificOutput.updatedToolOutput` for PostToolUse hooks (replaces current WARN-only behavior for Bash/Read/Write outputs)
- Active verification mode (TruffleHog-style "is this key actually live?")
- `--file-path` flag on `scan --stdin` to enable path-based allowlist for PostToolUse:Read

## [0.1.0] — 2026-07-27

### Added
- Initial release.
- Detection core: regex patterns (12 built-in providers), bash escape-hatch detector, entropy candidates.
- Claude Code plugin with 6 hook scripts covering 8 detection rows.
- CLI peer (`pip install token-hunt`) with `scan`, `list`, `close`, `watch` commands.
- Pattern layering: builtin → `~/.token-hunt/patterns.local.toml` → `./.token-hunt/patterns.local.toml`.
- Allowlist engine (path-based + fingerprint-based).
- `rotations.log` JSONL store with 72-hour OVERDUE tracking.
- Built-in providers: Z.ai, Anthropic, GitHub (classic + fine-grained), GitLab, Figma, PyPI, npm, Linear, Stripe, OpenAI, Slack.
- Bash escape-hatch detection (the unique IP — `${VAR:+SET}${VAR:-UNSET}` bug class).
- `TOKEN_HUNT_DISABLE=1` env var opt-out (skip all hooks).
- `TOKEN_HUNT_ALLOW=1` env var bypass (one-shot override of BLOCK hooks).
- Fail-closed behavior: scanner crashes BLOCK with bypass hint, never silently allow.
