"""Fake secrets for tests. All values match our regex patterns but are
obviously invalid (all-zeros, test prefixes). None will authenticate.
"""

# Format-valid but obviously fake. Match the regex, fail reality.
ZAI_KEY = "0" * 32 + "." + "0" * 16
ZAI_KEY_ALT = "a" * 32 + "." + "B" * 16

ANTHROPIC_KEY = "sk-ant-" + "0" * 95
GITHUB_PAT = "ghp_" + "0" * 36
GITHUB_FINE_PAT = "github_pat_" + "0" * 20 + "_" + "0" * 16
FIGMA_PAT = "figd_" + "0" * 40
PYPI_TOKEN = "pypi-" + "0" * 60
LINEAR_KEY = "lin_api_" + "0" * 40
STRIPE_SK = "sk_live_" + "0" * 24
OPENAI_KEY = "sk-" + "0" * 48
NPM_TOKEN = "npm_" + "0" * 36
SLACK_TOKEN = "xoxb-" + "0" * 30

# Status-check escape patterns (Jordan's bug class)
ESCAPE_PATTERN_DOLLAR_BRACE = 'echo ${ANTHROPIC_API_KEY:+SET}${ANTHROPIC_API_KEY:-UNSET}'
ESCAPE_PATTERN_ECHO = 'echo $GITHUB_TOKEN'
ESCAPE_PATTERN_PRINTENV = 'printenv STRIPE_SECRET_KEY'
ESCAPE_PATTERN_ENV_GREP = 'env | grep -i token'
ESCAPE_PATTERN_GREP_VAR = 'grep $DB_PASSWORD /etc/shadow'

# Legit status check (should NOT fire)
ESCAPE_SAFE_STATUS_CHECK = '[ -n "$ANTHROPIC_API_KEY" ] && echo SET'
ESCAPE_SAFE_WC = 'wc -c <<< "$ANTHROPIC_API_KEY"'

# Test fixture allowlist fingerprint (Task 7 uses this)
ALLOWLISTED_FAKE_KEY = "test_fixture_deadbeefdeadbeefdeadbeefdeadbeef.ABCDefgh1234567890"
