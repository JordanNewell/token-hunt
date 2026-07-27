#!/usr/bin/env bash
# token-hunt: PostToolUse Edit/Write hook. Defense-in-depth — same scan as
# pre-write but fires after the write completed (catches edge cases where
# pre-write was bypassed, e.g. via TOKEN_HUNT_ALLOW=1).

set -e

# Opt-out: TOKEN_HUNT_DISABLE=1 skips this hook entirely.
[ "${TOKEN_HUNT_DISABLE:-0}" = "1" ] && exit 0

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

content=$(echo "$input" | jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0
fi

result=$(echo "$content" | token-hunt scan --stdin --context PostToolUse:Write --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: write contained $count secret(s) — pre-write check was bypassed:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // "n/a"))"' >&2

exit 0
