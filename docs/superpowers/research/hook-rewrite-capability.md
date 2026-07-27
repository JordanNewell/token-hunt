# Hook Rewrite Capability — Research Finding

**Question:** Can Claude Code hooks modify tool I/O (rewrite prompts, edit tool output) before processing?

**Resolved:** 2026-07-27, via official docs at `https://code.claude.com/docs/en/hooks`

**Answer:** **Yes**, for tool I/O. No for the user prompt itself, but it can be augmented.

## Per-event capability matrix

| Event | Can rewrite? | Field | Notes |
|---|---|---|---|
| `PreToolUse` | yes | `hookSpecificOutput.updatedInput` | Replaces tool arguments before execution |
| `PostToolUse` | yes | `hookSpecificOutput.updatedToolOutput` | Replaces tool result after execution |
| `UserPromptSubmit` | **no** | (only `additionalContext` injection or block) | Cannot rewrite the user's literal prompt text |
| `MessageDisplay` | yes (display-only) | `displayContent` | Replaces text shown to user, but doesn't change transcript content |

For `PreToolUse`, also supports `permissionDecision: "allow" | "deny" | "ask" | "defer"` — same hook can rewrite AND decide permission.

## Exit code semantics

- **0**: success — stdout parsed for JSON output fields
- **2**: blocking error — blocks the action (event-dependent), stderr fed to Claude
- **1, 3+**: non-blocking error — shows notice, execution continues

`exit 2` blocks for `PreToolUse`, `UserPromptSubmit`, `Stop`, etc. Does NOT block for `PostToolUse`, `SessionStart`, `SessionEnd` (those just show stderr).

## JSON output schema (relevant events)

### PreToolUse (can rewrite tool input)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",  // or "deny", "ask", "defer"
    "permissionDecisionReason": "...",
    "updatedInput": {                // optional: replaces tool_input
      "command": "redacted-cmd"
    },
    "additionalContext": "..."
  }
}
```

### PostToolUse (can rewrite tool output)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "updatedToolOutput": "[REDACTED] secret removed from output",
    "additionalContext": "..."
  }
}
```

### UserPromptSubmit (cannot rewrite prompt; can inject context)

```json
{
  "decision": "block",           // optional: blocks prompt
  "reason": "...",
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "..."
  }
}
```

## Implications for token-hunt v0.1

The original spec assumed rewrite wasn't possible and proposed BLOCK+show-redacted-text as the fallback. **The reality is better.** Updated hook behavior:

| Hook | v0.1 spec behavior | Updated behavior |
|---|---|---|
| `UserPromptSubmit` | WARN (banner) | WARN (banner) — unchanged, can't rewrite prompt |
| `PreToolUse:Bash` | BLOCK | BLOCK (with `TOKEN_HUNT_ALLOW=1` bypass) — keep BLOCK, don't rewrite. Safer to force dev to fix command. |
| `PostToolUse:Bash` | WARN + log (can't redact) | **SILENT REDACT** via `updatedToolOutput` — replaces secret in transcript. Big upgrade. |
| `PostToolUse:Read` | WARN + log | **SILENT REDACT** via `updatedToolOutput` — same upgrade |
| `PreToolUse:Edit/Write` | BLOCK | BLOCK — keep. Writing a NEW secret to disk should be blocked, not silently redacted. |
| `PostToolUse:Edit/Write` | WARN + log | **SILENT REDACT** via `updatedToolOutput` |

## Why this is a big deal

The #1 leak vector — agent reads `~/.zcode/config.json` or `~/.claude/settings.json`, secret ends up in transcript — is now **fixable in place**. The PostToolUse hook rewrites the output before it hits the transcript. The agent never sees the secret. Jordan's "I just leaked your ANTHROPIC_AUTH_TOKEN by reading settings.json" incident from this session would not have leaked.

The UserPromptSubmit case is still WARN-only (can't rewrite the prompt), but for tool I/O we have full silent-redaction capability.

## Decision for v0.1.0

- **Implement silent redaction** via `updatedToolOutput` for all PostToolUse hooks (Tasks 19, 20, 21)
- **Keep BLOCK** for PreToolUse:Bash (escape hatch detection requires dev to fix command, not silently rewrite) and PreToolUse:Edit/Write (writing new secrets should be blocked, not redacted)
- **Keep WARN** for UserPromptSubmit (no rewrite possible anyway)

This is a strict upgrade from the spec. The hook scripts in Tasks 17-21 should emit JSON with `hookSpecificOutput.updatedToolOutput` for PostToolUse events instead of just printing warnings to stderr.

## Sources

- Official docs: `https://code.claude.com/docs/en/hooks`
- Verified: 2026-07-27 against current Claude Code (v2.0+)
- Sensitive-canary's "hooks can't rewrite prompts" claim was outdated — true only for UserPromptSubmit, false for PreToolUse and PostToolUse
