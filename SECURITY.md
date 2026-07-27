# Security Policy

## Reporting a Vulnerability

Email **security@jordannewell.com** with details and repro steps.

**Acknowledgment SLA: 72 hours** (solo maintainer with day-job + 15-agent fleet — 48h broke credibility when missed).

## Disclosure

- Reporter credited in release notes unless they prefer otherwise.
- Coordinated disclosure after fix ships.
- No bug bounty program (yet).

## Scope

- token-hunt itself (Python package + Claude Code plugin)
- The official pattern ruleset shipped in `src/token_hunt/patterns/builtin.toml`

## Out of scope

- Vulnerabilities in dependencies (report upstream)
- Leaks from user-supplied patterns in `~/.token-hunt/patterns.local.toml`
- Social engineering attacks against the maintainer
