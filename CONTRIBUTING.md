# Contributing

Thanks for considering a contribution.

## Setup

```bash
git clone https://github.com/JordanNewell/token-hunt
cd token-hunt
pip install -e ".[dev]"
pytest
```

## Development workflow

1. Open an issue describing the change (skip for trivial fixes).
2. Branch from `main`: `feat/<short-desc>` or `fix/<short-desc>`.
3. Add tests for new behavior. TDD preferred.
4. Run `pytest` and `ruff check .` before committing.
5. Open a PR — describe the change + link the issue.

## Adding a new provider pattern

1. Add a rule to `src/token_hunt/patterns/builtin.toml` (gitleaks-compatible TOML format).
2. Add provider metadata to `src/token_hunt/patterns/rotate-urls.toml`.
3. Add a fake-format test constant to `tests/fixtures.py`.
4. Add a detection test to `tests/test_regex_scanner.py`.

## Code style

- Python 3.10+ (use `from __future__ import annotations`).
- Line length 100 (ruff default).
- No AI-attribution trailers in commit messages.
- Tests required for all behavior changes.

## Commit message conventions

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.

72-char subject line. Body wraps at 80. Explain the *why* when non-obvious.
