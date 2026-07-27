#!/usr/bin/env bash
# token-hunt: PreToolUse Edit/Write hook. BLOCK writes of new secrets to disk.
# Catches "agent writes secrets into a new file" before the write happens.
#
# Bypass: TOKEN_HUNT_ALLOW=1 (e.g. intentionally writing test fixtures).

set -e

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

# Edit tool uses .new_string, Write tool uses .content
content=$(echo "$input" | jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if [ "${TOKEN_HUNT_ALLOW:-0}" = "1" ]; then
  exit 0
fi

if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. pip install token-hunt" >&2
  exit 0
fi

result=$(echo "$content" | token-hunt scan --stdin --context PreToolUse:Write --format json 2>&1) || {
  echo "🚫 token-hunt: scanner error. Verify write is safe, then TOKEN_HUNT_ALLOW=1." >&2
  exit 2
}

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚫 token-hunt: BLOCKED — refusing to write secret(s) to disk:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // "n/a"))"' >&2
echo "" >&2
echo "If intentional (e.g. tests/fixtures/), add to ~/.token-hunt/allowlist.toml." >&2

exit 2
