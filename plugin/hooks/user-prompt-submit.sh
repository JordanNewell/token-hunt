#!/usr/bin/env bash
# token-hunt: UserPromptSubmit hook. WARN on detected leaks (don't block).
# Jordan's design rule: respect the human's judgment on what they pasted.
#
# Note: Claude Code's UserPromptSubmit hook CANNOT rewrite the prompt
# (verified 2026-07-27 via official docs). Can only inject additionalContext
# or block. We WARN here — the human decides whether to rotate.

set -e

# Opt-out: TOKEN_HUNT_DISABLE=1 skips this hook entirely.
[ "${TOKEN_HUNT_DISABLE:-0}" = "1" ] && exit 0

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

prompt=$(echo "$input" | jq -r '.prompt // empty' 2>/dev/null || true)
[ -z "$prompt" ] && exit 0

# Fail-closed: if token-hunt isn't installed, instruct user (don't silently pass).
if ! command -v token-hunt >/dev/null 2>&1; then
  echo "⚠️  token-hunt: scanner not installed. Install with: pip install token-hunt" >&2
  exit 0  # WARN, not BLOCK — don't break the prompt over install issues
fi

result=$(echo "$prompt" | token-hunt scan --stdin --context UserPromptSubmit --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "⚠️  token-hunt: $count potential leak(s) detected in your prompt:" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // "n/a"))"' >&2
echo "" >&2
echo "The prompt was still sent — rotate any real keys at the URLs above." >&2

exit 0  # WARN, never BLOCK
