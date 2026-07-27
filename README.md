# token-hunt

> Catch secrets at chat time, not commit time.

[![release](https://img.shields.io/badge/release-0.1.0-blue)](https://github.com/JordanNewell/token-hunt/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)

Hook-based secret scanner for **Claude Code**, **Cursor**, **Aider**, and other AI CLIs. Catches leaks when you paste, when your agent reads, and when your agent's tools return — not at commit time when it's already too late.

## Why

Existing scanners (gitleaks, trufflehog, ggshield) scan **git history**. By the time you run `git commit`, your secret has been in the AI chat transcript for 30+ minutes — indexed by Anthropic, sync'd to other machines, possibly read by the agent and re-emitted in subsequent tool calls.

token-hunt catches at chat time. **Zero cloud, zero telemetry, fail-closed by default.**

## Install

**As a Claude Code plugin** (recommended):

```bash
claude plugin install token-hunt@JordanNewell
```

**As a standalone CLI**:

```bash
pip install token-hunt
```

## 60-second demo

```bash
# In one terminal:
pip install token-hunt

# Scan a file:
echo "ANTHROPIC_API_KEY=sk-ant-..." > /tmp/test.txt
token-hunt scan /tmp/test.txt

# Watch a directory (e.g. Claude Code transcript dir):
token-hunt watch ~/.claude/projects/

# List open leaks:
token-hunt list

# Close after rotating:
token-hunt close 1 --note "rotated at console.anthropic.com"
```

## Detection points

| Hook | What it sees | Action on leak |
|---|---|---|
| `UserPromptSubmit` | Your paste | WARN (banner) |
| `PreToolUse:Bash` | Command about to run | BLOCK (won't run) |
| `PostToolUse:Bash` | Command output | WARN + log (transcript already has it) |
| `PostToolUse:Read` | File contents | WARN + log |
| `PreToolUse:Edit/Write` | New file content | BLOCK |
| `PostToolUse:Edit/Write` | Echo | WARN + log |

## The unique feature: bash escape-hatch detection

token-hunt catches patterns where bash evaluates a secret into emitted text, even when the literal secret isn't in your input:

```bash
# BLOCKED — both branches run, leaks the value:
echo ${ANTHROPIC_API_KEY:+SET}${ANTHROPIC_API_KEY:-UNSET}

# BLOCKED — direct echo of secret var:
echo $GITHUB_TOKEN

# ALLOWED — correct status-check pattern:
[ -n "$ANTHROPIC_API_KEY" ] && echo SET
```

No other scanner detects this class.

## Configuration

Patterns layer (later extends earlier):

1. `token_hunt/patterns/builtin.toml` (ships with package)
2. `~/.token-hunt/patterns.local.toml` (machine-local, gitignored)
3. `./.token-hunt/patterns.local.toml` (repo-local, gitignored)

Allowlist (test fixtures, etc.):

`~/.token-hunt/allowlist.toml`:
```toml
fingerprints = [
  "abc123def456...",  # SHA-256 first 16 chars of allowlisted value
]
```

Per-repo opt-out:
```bash
export TOKEN_HUNT_DISABLE=1
# or
touch .token-hunt/disable
```

## Bypass

```bash
TOKEN_HUNT_ALLOW=1 <command>  # one-shot bypass (use sparingly)
```

## Built-in providers

Z.ai · Anthropic · GitHub (classic + fine-grained) · GitLab · Figma · PyPI · npm · Linear · Stripe · OpenAI · Slack

## Comparison

| Tool | Surface | Local-only | Fail-closed | Escape hatch | Fleet sync |
|---|---|---|---|---|---|
| **token-hunt** | Claude Code + CLI | yes | yes | **yes** | v0.2 |
| sensitive-canary | Claude Code | yes | yes | no | no |
| ggshield | Claude Code | no (cloud API) | no (fail-open) | no | no |
| gitleaks | git only | yes | n/a | no | no |

## License

MIT. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md). 72-hour acknowledgment SLA.
