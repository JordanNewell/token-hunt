#!/usr/bin/env bash
# token-hunt: PostToolUse Bash hook. WARN when command output contained secrets.
# Output is already in transcript by now — PostToolUse can't undo the write,
# but we CAN warn loudly + log to rotations.log so dev can rotate.
#
# v0.1.1 roadmap: use hookSpecificOutput.updatedToolOutput to silently redact
# the secret in transcript (research note: docs/superpowers/research/hook-rewrite-capability.md).
# For v0.1, WARN-only — requires CLI extension to ship cleanly.

set -e

# Opt-out: TOKEN_HUNT_DISABLE=1 skips this hook entirely.
[ "${TOKEN_HUNT_DISABLE:-0}" = "1" ] && exit 0

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

stdout=$(echo "$input" | jq -r '.tool_response.stdout // empty' 2>/dev/null || true)
[ -z "$stdout" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0  # silent if not installed — post-hoc warning is non-critical
fi

# Pro integration: if token-hunt-pro installed + license active, silently redact.
if command -v token-hunt-pro >/dev/null 2>&1 && \
   token-hunt-pro status 2>/dev/null | grep -qi "tier:"; then
  redacted=$(echo "$stdout" | token-hunt-pro redact --stdin --context PostToolUse:Bash 2>/dev/null) || redacted=""
  if [ -n "$redacted" ] && [ "$redacted" != "$stdout" ]; then
    # Emit Claude Code PostToolUse JSON to replace the tool output
    jq -n --arg r "$redacted" '{
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: $r
      }
    }' >&1
    exit 0
  fi
fi
# Fall through to WARN-only behavior if Pro not active or no leaks found

result=$(echo "$stdout" | token-hunt scan --stdin --context PostToolUse:Bash --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: $count secret(s) appeared in command output (now in transcript):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // "n/a"))"' >&2
echo "" >&2
echo "Action required: rotate the listed keys before continuing." >&2

exit 0
