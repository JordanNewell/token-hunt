#!/usr/bin/env bash
# token-hunt: PostToolUse Read hook. Warn when a read file contained secrets.
# Catches the "agent reads settings.json" leak class.
#
# This is the hook that would have prevented the ANTHROPIC_AUTH_TOKEN leak
# in this very session (agent read ~/.claude/settings.json, key ended up
# in transcript — see research/hook-rewrite-capability.md for the v0.1.1
# silent-redaction upgrade path).

set -e

# Opt-out: TOKEN_HUNT_DISABLE=1 skips this hook entirely.
[ "${TOKEN_HUNT_DISABLE:-0}" = "1" ] && exit 0

input=$(cat 2>/dev/null || echo "")
[ -z "$input" ] && exit 0

content=$(echo "$input" | jq -r '.tool_response.content // empty' 2>/dev/null || true)
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
[ -z "$content" ] && exit 0

if ! command -v token-hunt >/dev/null 2>&1; then
  exit 0
fi

# Pro integration: if token-hunt-pro installed + license active, silently redact.
if command -v token-hunt-pro >/dev/null 2>&1 && \
   token-hunt-pro status 2>/dev/null | grep -qi "tier:"; then
  redacted=$(echo "$content" | token-hunt-pro redact --stdin --context PostToolUse:Read 2>/dev/null) || redacted=""
  if [ -n "$redacted" ] && [ "$redacted" != "$content" ]; then
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

result=$(echo "$content" | token-hunt scan --stdin --context PostToolUse:Read --format json 2>/dev/null || true)
[ -z "$result" ] && exit 0

count=$(echo "$result" | jq -r '.count // 0' 2>/dev/null || echo "0")
[ "$count" = "0" ] && exit 0

echo "🚨 token-hunt: read of $file_path contained $count secret(s):" >&2
echo "$result" | jq -r '.matches[] | "  - \(.kind) (rotate: \(.rotate_url // "n/a"))"' >&2
echo "" >&2
echo "The secret is now in transcript. Rotate before continuing." >&2

exit 0
