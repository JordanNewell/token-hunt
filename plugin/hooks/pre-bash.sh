#!/usr/bin/env bash
# token-hunt: PreToolUse Bash hook. BLOCK commands that would leak secrets.
# This is the only BLOCK-level hook — head the leak off before subprocess runs.
#
# Catches TWO classes:
# 1. Literal secret in command (e.g. `echo sk-ant-...`)
# 2. Escape-hatch patterns that evaluate secrets into emitted text
#    (e.g. `echo ${VAR:+SET}${VAR:-UNSET}` — Jordan's bug class)
#
# Bypass: TOKEN_HUNT_ALLOW=1 env var (used when dev has verified command is safe).

set -e

# Opt-out: TOKEN_HUNT_DISABLE=1 skips this hook entirely.
[ "${TOKEN_HUNT_DISABLE:-0}" = "1" ] && exit 0

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

cmd=$(echo "$input" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -z "$cmd" ] && exit 0

# Operator bypass
if [ "${TOKEN_HUNT_ALLOW:-0}" = "1" ]; then
  exit 0
fi

if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. pip install token-hunt" >&2
  exit 0
fi

# Fail-closed: if scan throws (e.g. corrupted install), BLOCK with bypass hint.
result=$(echo "$cmd" | token-hunt scan --stdin --context PreToolUse:Bash --format json 2>&1) || {
  echo "🚫 token-hunt: scanner error. Investigate before running this command." >&2
  echo "    To bypass: TOKEN_HUNT_ALLOW=1 (but verify the command is safe first)" >&2
  echo "    Error: $result" >&2
  exit 2
}

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚫 token-hunt: BLOCKED — command would leak $count secret(s):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (line \(.line))"' >&2
echo "" >&2
echo "If this is a false positive, re-run with TOKEN_HUNT_ALLOW=1 env var." >&2

exit 2  # BLOCK
