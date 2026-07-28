# token-hunt Pro v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `token-hunt-pro` v0.2.0 as a separate commercial Python package with (a) license validation, (b) silent redaction via PostToolUse `updatedToolOutput`, and (c) active verification via provider APIs. Revenue-ready: pairs with the external Stripe + Supabase setup in the Phase 3-4 operational checklist.

**Architecture:** New sibling package `token-hunt-pro` at `E:/dev/projects/token-hunt-pro/`. Pro installs alongside free `token-hunt`. Free hooks detect Pro via PATH check; when present, PostToolUse hooks delegate to `token-hunt-pro redact` for silent redaction (vs WARN-only fallback). License validation is offline — ed25519-signed keys validated against a public key shipped in the package; private key stays with Jordan, never on disk in the repo.

**Tech Stack:** Python 3.10+, stdlib + `cryptography` (ed25519) + `httpx` (provider API checks) + `click` (CLI), pytest + responses for testing. MIT-equivalent commercial license.

**Spec:** `docs/superpowers/specs/2026-07-27-token-hunt-pro-tier-design.md` (in token-hunt repo)

**Scope note:** This plan covers Tasks 1-7 (local code, fully TDD-able). Phase 3-4 (Stripe billing, Supabase license server, email delivery, landing page, launch) is a separate operational checklist at `docs/superpowers/plans/2026-07-27-token-hunt-pro-v0.2-gtm.md` (created in Task 8) — not an implementation plan because tasks require external account setup Jordan must do himself.

---

## File Structure

New repo at `E:/dev/projects/token-hunt-pro/`:

```
token-hunt-pro/
├── pyproject.toml                   # Task 1
├── LICENSE-PRO                      # Task 1 (commercial, source-available)
├── .gitignore                       # Task 1
├── README.md                        # Task 1 (skeleton, full version in Phase 4)
├── src/token_hunt_pro/
│   ├── __init__.py                  # Task 1
│   ├── types.py                     # Task 2 (License dataclass + Tier enum)
│   ├── license_codec.py             # Task 2 (encode/decode + ed25519 sign)
│   ├── license_validator.py         # Task 3 (validate_key, offline)
│   ├── keys/
│   │   └── license_pubkey.pem       # Task 3 (ed25519 public key, ships in package)
│   ├── store_license.py             # Task 4 (read/write ~/.token-hunt/license.json)
│   ├── cli.py                       # Task 4 (activate), Task 5 (redact), Task 6 (verify)
│   ├── redact.py                    # Task 5 (redact_value helpers)
│   └── verifiers/
│       ├── __init__.py              # Task 6 (registry)
│       ├── github.py                # Task 6 (GitHub /user check)
│       ├── stripe.py                # Task 6 (Stripe /v1/account check)
│       └── slack.py                 # Task 6 (Slack auth.test check)
├── tests/
│   ├── conftest.py                  # Task 1 (fixtures: temp home, ed25519 keypair)
│   ├── test_license_codec.py        # Task 2
│   ├── test_license_validator.py    # Task 3
│   ├── test_store_license.py        # Task 4
│   ├── test_cli_activate.py         # Task 4
│   ├── test_redact.py               # Task 5
│   ├── test_cli_redact.py           # Task 5
│   ├── test_verifiers.py            # Task 6
│   └── test_cli_verify.py           # Task 6
└── scripts/
    └── generate_keypair.py          # Task 3 (Jordan's tool for making the master keypair)
```

Free `token-hunt` repo modifications (in `E:/dev/projects/token-hunt/`):
- `plugin/hooks/post-bash.sh` — modified to detect Pro and delegate redaction (Task 5)
- `plugin/hooks/post-read.sh` — modified to detect Pro and delegate redaction (Task 5)
- `plugin/hooks/post-write.sh` — modified to detect Pro and delegate redaction (Task 5)

---

## Phase 1: License Infrastructure (Tasks 1-4)

### Task 1: token-hunt-pro package scaffold

**Files:**
- Create: `E:/dev/projects/token-hunt-pro/pyproject.toml`
- Create: `E:/dev/projects/token-hunt-pro/LICENSE-PRO`
- Create: `E:/dev/projects/token-hunt-pro/.gitignore`
- Create: `E:/dev/projects/token-hunt-pro/README.md` (skeleton)
- Create: `E:/dev/projects/token-hunt-pro/src/token_hunt_pro/__init__.py`
- Create: `E:/dev/projects/token-hunt-pro/tests/conftest.py`

- [ ] **Step 1: Create the new repo directory + init git**

```bash
mkdir -p /e/dev/projects/token-hunt-pro
cd /e/dev/projects/token-hunt-pro
git init -b main
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "token-hunt-pro"
version = "0.2.0"
description = "Pro tier for token-hunt: silent redaction + active verification. Requires license key."
readme = "README.md"
requires-python = ">=3.10"
authors = [{ name = "Jordan Newell", email = "jordan@jordannewell.com" }]
license = { text = "Commercial (see LICENSE-PRO)" }
classifiers = [
    "License :: Other/Proprietary License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "token-hunt>=0.1.0",
    "cryptography>=42.0.0",
    "httpx>=0.27.0",
    "click>=8.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=5.0.0",
    "ruff>=0.6.0",
    "responses>=0.25.0",
]

[project.scripts]
token-hunt-pro = "token_hunt_pro.cli:main"

[project.urls]
Homepage = "https://jordannewell.com/products/token-hunt-pro"

[tool.hatch.build.targets.wheel]
packages = ["src/token_hunt_pro"]

[tool.hatch.build.targets.wheel.shared-data]
"src/token_hunt_pro/keys" = "token_hunt_pro/keys"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers"
```

- [ ] **Step 3: Write `LICENSE-PRO` (commercial, source-available)**

```
token-hunt Pro Commercial License
Version 1.0, 2026-07-27

Copyright (c) 2026 Jordan Newell. All rights reserved.

1. GRANT. Subject to payment of the applicable license fee and continued
   compliance with this License, Jordan Newell ("Licensor") grants you
   ("Licensee") a non-exclusive, non-transferable, non-sublicensable,
   revocable license to:
   (a) install and execute the Software for Licensee's internal business
       or personal use;
   (b) make modifications for Licensee's internal use.

2. RESTRICTIONS. Licensee shall not:
   (a) redistribute, sublicense, sell, rent, lease, or otherwise make the
       Software available to any third party;
   (b) use the Software to provide a competing commercial service;
   (c) remove or alter any proprietary notices;
   (d) use the Software beyond the scope of the tier purchased (Solo, Team,
       or Enterprise as defined at https://jordannewell.com/products/token-hunt-pro).

3. SOURCE AVAILABILITY. Source code is provided to paying Licensees for
   internal use and audit only. Recipients may not redistribute the source.

4. INTELLECTUAL PROPERTY. All right, title, and interest in and to the
   Software remain with Licensor.

5. TERMINATION. This License terminates automatically upon breach or
   expiration of the license key. Upon termination, Licensee shall cease
   all use of the Software and destroy all copies.

6. DISCLAIMER. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
   KIND. IN NO EVENT SHALL LICENSOR BE LIABLE FOR DAMAGES ARISING FROM
   THE USE OR INABILITY TO USE THE SOFTWARE.

For license inquiries: jordan@jordannewell.com
```

- [ ] **Step 4: Write `.gitignore`**

```
__pycache__/
*.py[cod]
*.egg-info/
*.egg
build/
dist/
.pytest_cache/
.coverage
.venv/
venv/
.DS_Store
*.log

# Critical: never commit the master private key
master_private_key.pem
*.private-key
*.private_key
secrets/
```

- [ ] **Step 5: Write `README.md` skeleton**

```markdown
# token-hunt-pro

> Silent redaction + active verification for [token-hunt](https://github.com/JordanNewell/token-hunt).

**Status:** v0.2.0 in development. Commercial license required — see `LICENSE-PRO`.

## Install (post-launch)

```bash
pip install token-hunt-pro
token-hunt-pro activate <license-key>
```

## Pricing

See https://jordannewell.com/products/token-hunt-pro/

## License

Commercial. Source-available to paying customers. See `LICENSE-PRO`.
```

- [ ] **Step 6: Write `src/token_hunt_pro/__init__.py`**

```python
"""token-hunt-pro: silent redaction + active verification for token-hunt."""

__version__ = "0.2.0"
```

- [ ] **Step 7: Write `tests/conftest.py`**

```python
import pytest
from pathlib import Path


@pytest.fixture
def tmp_home(tmp_path, monkeypatch):
    """Redirect $HOME to a tmp dir for license file tests."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    return fake_home


@pytest.fixture
def ed25519_keypair(tmp_path):
    """Generate an ed25519 keypair for tests. Returns (private_pem, public_pem) Paths."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = tmp_path / "test_private.pem"
    pub_path = tmp_path / "test_public.pem"
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    return priv_path, pub_path
```

- [ ] **Step 8: Verify install + collect**

Run:
```bash
cd /e/dev/projects/token-hunt-pro
py -m pip install -e ".[dev]"
py -m pytest --collect-only
```
Expected: 0 tests collected, no errors.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml LICENSE-PRO .gitignore README.md src/ tests/
git commit -m "scaffold: token-hunt-pro package layout, commercial license"
```

---

### Task 2: License dataclass + ed25519 codec

**Files:**
- Create: `src/token_hunt_pro/types.py`
- Create: `src/token_hunt_pro/license_codec.py`
- Create: `tests/test_license_codec.py`

- [ ] **Step 1: Write `tests/test_license_codec.py` (failing test first — TDD)**

```python
import base64
import json
from datetime import datetime, timezone

import pytest

from token_hunt_pro.types import License, Tier
from token_hunt_pro.license_codec import encode_license, decode_license


def _make_license(**overrides):
    defaults = {
        "tier": Tier.SOLO,
        "customer_email": "user@example.com",
        "customer_id": "cust_abc",
        "issued_at": datetime(2026, 7, 27, tzinfo=timezone.utc),
        "expires_at": datetime(2027, 7, 27, tzinfo=timezone.utc),
        "seats": 1,
    }
    defaults.update(overrides)
    return License(**defaults)


def test_license_dataclass_immutable():
    lic = _make_license()
    with pytest.raises((AttributeError, TypeError)):
        lic.tier = Tier.TEAM  # frozen=True


def test_encode_produces_thp_prefixed_string(ed25519_keypair):
    priv, _ = ed25519_keypair
    lic = _make_license()
    encoded = encode_license(lic, private_key_path=priv)
    assert encoded.startswith("thp_")


def test_encode_then_decode_roundtrip(ed25519_keypair):
    priv, pub = ed25519_keypair
    original = _make_license(tier=Tier.TEAM, customer_email="other@example.com", seats=5)
    encoded = encode_license(original, private_key_path=priv)
    decoded = decode_license(encoded, public_key_path=pub)
    assert decoded.tier == Tier.TEAM
    assert decoded.customer_email == "other@example.com"
    assert decoded.seats == 5


def test_decode_rejects_tampered_payload(ed25519_keypair):
    priv, pub = ed25519_keypair
    lic = _make_license()
    encoded = encode_license(lic, private_key_path=priv)
    # Tamper with the payload portion
    prefix, rest = encoded.split("_", 1)
    payload_b64, sig_b64 = rest.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    payload["tier"] = "enterprise"  # attacker tries to upgrade
    tampered_payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")
    tampered = f"thp_{tampered_payload_b64}.{sig_b64}"
    with pytest.raises(ValueError, match="signature"):
        decode_license(tampered, public_key_path=pub)


def test_decode_rejects_wrong_key(ed25519_keypair, tmp_path):
    """Key generated for sign, different key used for verify → reject."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    signing_priv, _ = ed25519_keypair

    # Generate a separate verifier keypair
    other_priv = Ed25519PrivateKey.generate()
    other_pub_bytes = other_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    other_pub_path = tmp_path / "other_public.pem"
    other_pub_path.write_bytes(other_pub_bytes)

    lic = _make_license()
    encoded = encode_license(lic, private_key_path=signing_priv)
    with pytest.raises(ValueError, match="signature"):
        decode_license(encoded, public_key_path=other_pub_path)


def test_decode_rejects_malformed_key_string(ed25519_keypair):
    priv, pub = ed25519_keypair
    with pytest.raises(ValueError):
        decode_license("not-a-valid-key", public_key_path=pub)


def test_decode_rejects_missing_sig(ed25519_keypair):
    priv, pub = ed25519_keypair
    encoded = encode_license(_make_license(), private_key_path=priv)
    # Strip the signature
    no_sig = encoded.split(".")[0]
    with pytest.raises(ValueError, match="format"):
        decode_license(no_sig, public_key_path=pub)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_license_codec.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Write `src/token_hunt_pro/types.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Tier(str, Enum):
    SOLO = "solo"
    TEAM = "team"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class License:
    """A validated license. Immutable once parsed from a license key."""
    tier: Tier
    customer_email: str
    customer_id: str
    issued_at: datetime
    expires_at: datetime
    seats: int = 1
```

- [ ] **Step 4: Write `src/token_hunt_pro/license_codec.py`**

```python
from __future__ import annotations
import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from token_hunt_pro.types import License, Tier

KEY_PREFIX = "thp_"


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _license_to_payload(lic: License) -> dict:
    return {
        "tier": lic.tier.value,
        "email": lic.customer_email,
        "customer_id": lic.customer_id,
        "issued_at": lic.issued_at.isoformat(),
        "expires_at": lic.expires_at.isoformat(),
        "seats": lic.seats,
    }


def _payload_to_license(payload: dict) -> License:
    return License(
        tier=Tier(payload["tier"]),
        customer_email=payload["email"],
        customer_id=payload["customer_id"],
        issued_at=datetime.fromisoformat(payload["issued_at"]),
        expires_at=datetime.fromisoformat(payload["expires_at"]),
        seats=payload.get("seats", 1),
    )


def _load_private_key(path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = Path(path).read_bytes()
    return serialization.load_pem_private_key(raw, password=None)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    return serialization.load_pem_public_key(raw)


def encode_license(lic: License, private_key_path: Union[str, Path]) -> str:
    """Encode + sign. Returns 'thp_<b64payload>.<b64sig>'."""
    priv = _load_private_key(Path(private_key_path))
    payload_bytes = json.dumps(
        _license_to_payload(lic), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig = priv.sign(payload_bytes)
    return f"{KEY_PREFIX}{_b64_encode(payload_bytes)}.{_b64_encode(sig)}"


def decode_license(encoded: str, public_key_path: Union[str, Path]) -> License:
    """Verify sig + parse payload. Raises ValueError on any failure."""
    if not encoded.startswith(KEY_PREFIX):
        raise ValueError("invalid format: missing thp_ prefix")
    body = encoded[len(KEY_PREFIX):]
    if "." not in body:
        raise ValueError("invalid format: missing signature delimiter")
    payload_b64, sig_b64 = body.split(".", 1)
    if not payload_b64 or not sig_b64:
        raise ValueError("invalid format: empty payload or signature")
    try:
        payload_bytes = _b64_decode(payload_b64)
        sig = _b64_decode(sig_b64)
    except Exception as e:
        raise ValueError(f"invalid format: base64 decode failed: {e}") from e

    pub = _load_public_key(Path(public_key_path))
    try:
        pub.verify(sig, payload_bytes)
    except InvalidSignature as e:
        raise ValueError("invalid signature: key may be tampered or signed by wrong key") from e

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid payload: not JSON: {e}") from e

    return _payload_to_license(payload)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `py -m pytest tests/test_license_codec.py -v`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add src/token_hunt_pro/types.py src/token_hunt_pro/license_codec.py tests/test_license_codec.py
git commit -m "license: ed25519-signed codec with tamper detection"
```

---

### Task 3: License validation library + keypair generator

**Files:**
- Create: `src/token_hunt_pro/license_validator.py`
- Create: `src/token_hunt_pro/keys/.gitkeep`
- Create: `scripts/generate_keypair.py`
- Create: `tests/test_license_validator.py`

- [ ] **Step 1: Generate the master keypair (Jordan's one-time action)**

Run:
```bash
mkdir -p /e/dev/projects/token-hunt-pro/scripts
mkdir -p /e/dev/projects/token-hunt-pro/src/token_hunt_pro/keys
cd /e/dev/projects/token-hunt-pro
py -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
open('master_private_key.pem', 'wb').write(priv_bytes)  # gitignored
open('src/token_hunt_pro/keys/license_pubkey.pem', 'wb').write(pub_bytes)  # ships in package
print('Generated. KEEP master_private_key.pem OFF git — .gitignored.')
"
```

- [ ] **Step 2: Write `scripts/generate_keypair.py` (documented for Jordan's future use)**

```python
#!/usr/bin/env python3
"""Generate a fresh ed25519 master keypair for token-hunt-pro license signing.

Run once per master key rotation. NEVER commit master_private_key.pem.

Usage:
    py scripts/generate_keypair.py
"""
from __future__ import annotations
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def main():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    repo = Path(__file__).parent.parent
    priv_path = repo / "master_private_key.pem"
    pub_path = repo / "src" / "token_hunt_pro" / "keys" / "license_pubkey.pem"

    if priv_path.exists():
        raise SystemExit(f"REFUSING: {priv_path} already exists. Rotate by hand after revoking all keys.")

    priv_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"wrote {priv_path} (gitignored — DO NOT COMMIT)")
    print(f"wrote {pub_path} (ships in package)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Write `tests/test_license_validator.py`**

```python
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from token_hunt_pro.types import License, Tier
from token_hunt_pro.license_codec import encode_license
from token_hunt_pro.license_validator import validate_key, ValidationError


def _make_valid_license(**overrides):
    defaults = {
        "tier": Tier.SOLO,
        "customer_email": "user@example.com",
        "customer_id": "cust_abc",
        "issued_at": datetime.now(timezone.utc) - timedelta(days=1),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=365),
        "seats": 1,
    }
    defaults.update(overrides)
    return License(**defaults)


def test_validate_key_accepts_unexpired_license(ed25519_keypair):
    priv, _ = ed25519_keypair
    lic = _make_valid_license()
    key = encode_license(lic, private_key_path=priv)
    # Patch: validator uses the SHIPPED pubkey, but for tests we monkeypatch
    import token_hunt_pro.license_validator as lv
    orig = lv._PUBKEY_PATH
    _, pub = ed25519_keypair
    lv._PUBKEY_PATH = pub
    try:
        validated = validate_key(key)
        assert validated.tier == Tier.SOLO
        assert validated.customer_email == "user@example.com"
    finally:
        lv._PUBKEY_PATH = orig


def test_validate_key_rejects_expired(ed25519_keypair):
    priv, _ = ed25519_keypair
    _, pub = ed25519_keypair
    expired = _make_valid_license(
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    key = encode_license(expired, private_key_path=priv)
    import token_hunt_pro.license_validator as lv
    orig = lv._PUBKEY_PATH
    lv._PUBKEY_PATH = pub
    try:
        with pytest.raises(ValidationError, match="expired"):
            validate_key(key)
    finally:
        lv._PUBKEY_PATH = orig


def test_validate_key_rejects_tampered(ed25519_keypair):
    priv, pub = ed25519_keypair
    key = encode_license(_make_valid_license(), private_key_path=priv)
    # Tamper: change last char of payload
    body = key.split("_", 1)[1]
    payload_b64, sig_b64 = body.split(".", 1)
    tampered_payload = payload_b64[:-2] + ("AA" if not payload_b64.endswith("AA") else "BB")
    tampered = f"thp_{tampered_payload}.{sig_b64}"
    import token_hunt_pro.license_validator as lv
    orig = lv._PUBKEY_PATH
    lv._PUBKEY_PATH = pub
    try:
        with pytest.raises(ValidationError):
            validate_key(tampered)
    finally:
        lv._PUBKEY_PATH = orig


def test_validate_key_rejects_malformed():
    with pytest.raises(ValidationError, match="format"):
        validate_key("garbage")
    with pytest.raises(ValidationError, match="format"):
        validate_key("")
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `py -m pytest tests/test_license_validator.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 5: Write `src/token_hunt_pro/license_validator.py`**

```python
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path

from token_hunt_pro.license_codec import decode_license
from token_hunt_pro.types import License

# Path to the ed25519 public key shipped in the package.
# The matching private key is held OFFLINE by Jordan — never in the repo.
_PUBKEY_PATH = Path(__file__).parent / "keys" / "license_pubkey.pem"


class ValidationError(ValueError):
    """Raised when a license key fails validation."""


def validate_key(encoded: str) -> License:
    """Validate an encoded license key. Raises ValidationError on any failure.

    Validation steps:
    1. Decode + verify ed25519 signature against shipped public key
    2. Check expires_at is in the future
    3. Return the parsed License dataclass

    All checks are offline — no phone-home, no network calls.
    """
    try:
        lic = decode_license(encoded, public_key_path=_PUBKEY_PATH)
    except ValueError as e:
        raise ValidationError(f"invalid license format or signature: {e}") from e

    now = datetime.now(timezone.utc)
    if lic.expires_at <= now:
        raise ValidationError(
            f"license expired on {lic.expires_at.date().isoformat()}"
        )

    return lic
```

- [ ] **Step 6: Create `src/token_hunt_pro/keys/.gitkeep`**

```bash
touch /e/dev/projects/token-hunt-pro/src/token_hunt_pro/keys/.gitkeep
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `py -m pytest tests/test_license_validator.py -v`
Expected: 4 passed.

- [ ] **Step 8: Commit**

```bash
git add src/token_hunt_pro/license_validator.py src/token_hunt_pro/keys/ scripts/generate_keypair.py tests/test_license_validator.py
git commit -m "license: offline ed25519 validator + master keypair generator"
```

---

### Task 4: Activate CLI + license store

**Files:**
- Create: `src/token_hunt_pro/store_license.py`
- Create: `src/token_hunt_pro/cli.py` (initial scaffold + `activate` command)
- Create: `tests/test_store_license.py`
- Create: `tests/test_cli_activate.py`

- [ ] **Step 1: Write `tests/test_store_license.py` (TDD)**

```python
import json
from pathlib import Path


def test_save_license_writes_json(tmp_home):
    from token_hunt_pro.store_license import save_validated_license
    from token_hunt_pro.types import License, Tier
    from datetime import datetime, timezone

    lic = License(
        tier=Tier.TEAM,
        customer_email="user@example.com",
        customer_id="cust_abc",
        issued_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        expires_at=datetime(2027, 7, 27, tzinfo=timezone.utc),
        seats=5,
    )
    save_validated_license(lic)
    license_file = tmp_home / ".token-hunt" / "license.json"
    assert license_file.is_file()
    data = json.loads(license_file.read_text())
    assert data["tier"] == "team"
    assert data["customer_email"] == "user@example.com"
    assert data["seats"] == 5


def test_load_license_returns_none_when_missing(tmp_home):
    from token_hunt_pro.store_license import load_stored_license
    assert load_stored_license() is None


def test_load_license_round_trips_saved_data(tmp_home):
    from token_hunt_pro.store_license import save_validated_license, load_stored_license
    from token_hunt_pro.types import License, Tier
    from datetime import datetime, timezone

    original = License(
        tier=Tier.ENTERPRISE,
        customer_email="bigco@example.com",
        customer_id="cust_big",
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        seats=50,
    )
    save_validated_license(original)
    loaded = load_stored_license()
    assert loaded is not None
    assert loaded.tier == Tier.ENTERPRISE
    assert loaded.customer_email == "bigco@example.com"
    assert loaded.seats == 50


def test_clear_license_removes_file(tmp_home):
    from token_hunt_pro.store_license import save_validated_license, clear_stored_license, load_stored_license
    from token_hunt_pro.types import License, Tier
    from datetime import datetime, timezone

    save_validated_license(License(
        tier=Tier.SOLO, customer_email="x@y.z", customer_id="c",
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
    ))
    assert (tmp_home / ".token-hunt" / "license.json").is_file()
    clear_stored_license()
    assert not (tmp_home / ".token-hunt" / "license.json").is_file()
    assert load_stored_license() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_store_license.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Write `src/token_hunt_pro/store_license.py`**

```python
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from token_hunt_pro.types import License, Tier


def _license_path() -> Path:
    return Path.home() / ".token-hunt" / "license.json"


def save_validated_license(lic: License) -> None:
    """Persist validated license to ~/.token-hunt/license.json.

    Stored as JSON. Cleared by `clear_stored_license()`."""
    path = _license_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "tier": lic.tier.value,
        "customer_email": lic.customer_email,
        "customer_id": lic.customer_id,
        "issued_at": lic.issued_at.isoformat(),
        "expires_at": lic.expires_at.isoformat(),
        "seats": lic.seats,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_stored_license() -> Optional[License]:
    """Read validated license from disk. Returns None if not present."""
    path = _license_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return License(
            tier=Tier(data["tier"]),
            customer_email=data["customer_email"],
            customer_id=data["customer_id"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            seats=data.get("seats", 1),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def clear_stored_license() -> None:
    """Remove the stored license file. Idempotent."""
    path = _license_path()
    if path.is_file():
        path.unlink()
```

- [ ] **Step 4: Run store tests to verify they pass**

Run: `py -m pytest tests/test_store_license.py -v`
Expected: 4 passed.

- [ ] **Step 5: Write `tests/test_cli_activate.py`**

```python
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from token_hunt_pro.cli import main
from token_hunt_pro.types import License, Tier
from token_hunt_pro.license_codec import encode_license


@pytest.fixture
def runner():
    return CliRunner()


def _make_key(ed25519_keypair, **overrides):
    priv, _ = ed25519_keypair
    defaults = {
        "tier": Tier.SOLO,
        "customer_email": "user@example.com",
        "customer_id": "cust_abc",
        "issued_at": datetime.now(timezone.utc) - timedelta(days=1),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=365),
        "seats": 1,
    }
    defaults.update(overrides)
    return encode_license(License(**defaults), private_key_path=priv)


def test_activate_writes_license_file(runner, tmp_home, ed25519_keypair, monkeypatch):
    key = _make_key(ed25519_keypair)
    _, pub = ed25519_keypair
    import token_hunt_pro.license_validator as lv
    monkeypatch.setattr(lv, "_PUBKEY_PATH", pub)

    result = runner.invoke(main, ["activate", key])
    assert result.exit_code == 0, result.output
    assert "activated" in result.output.lower()
    assert (tmp_home / ".token-hunt" / "license.json").is_file()


def test_activate_rejects_invalid_key(runner, tmp_home, ed25519_keypair, monkeypatch):
    _, pub = ed25519_keypair
    import token_hunt_pro.license_validator as lv
    monkeypatch.setattr(lv, "_PUBKEY_PATH", pub)

    result = runner.invoke(main, ["activate", "garbage-key"])
    assert result.exit_code != 0
    assert "invalid" in result.output.lower() or "error" in result.output.lower()
    assert not (tmp_home / ".token-hunt" / "license.json").is_file()


def test_activate_status_shows_active(runner, tmp_home, ed25519_keypair, monkeypatch):
    key = _make_key(ed25519_keypair, tier=Tier.TEAM, customer_email="team@company.com", seats=5)
    _, pub = ed25519_keypair
    import token_hunt_pro.license_validator as lv
    monkeypatch.setattr(lv, "_PUBKEY_PATH", pub)

    runner.invoke(main, ["activate", key])
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "team" in result.output.lower()
    assert "team@company.com" in result.output


def test_status_when_no_license(runner, tmp_home):
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "no license" in result.output.lower() or "not activated" in result.output.lower()
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `py -m pytest tests/test_cli_activate.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 7: Write `src/token_hunt_pro/cli.py`**

```python
"""token-hunt-pro CLI entry point."""
from __future__ import annotations
import sys

import click

from token_hunt_pro import __version__


@click.group()
@click.version_option(__version__, "--version")
def main() -> None:
    """token-hunt-pro: silent redaction + active verification. Requires license."""


@main.command()
@click.argument("license_key")
def activate(license_key: str) -> None:
    """Validate + store a license key."""
    from token_hunt_pro.license_validator import validate_key, ValidationError
    from token_hunt_pro.store_license import save_validated_license

    try:
        lic = validate_key(license_key)
    except ValidationError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)

    save_validated_license(lic)
    click.echo(
        f"activated: {lic.tier.value} tier for {lic.customer_email} "
        f"(seats: {lic.seats}, expires: {lic.expires_at.date().isoformat()})"
    )


@main.command()
def status() -> None:
    """Show current license status."""
    from token_hunt_pro.store_license import load_stored_license

    lic = load_stored_license()
    if lic is None:
        click.echo("no license active. Run: token-hunt-pro activate <key>")
        return
    click.echo(
        f"tier: {lic.tier.value}\n"
        f"customer: {lic.customer_email}\n"
        f"seats: {lic.seats}\n"
        f"expires: {lic.expires_at.date().isoformat()}"
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli_activate.py -v`
Expected: 4 passed.

- [ ] **Step 9: Commit**

```bash
git add src/token_hunt_pro/store_license.py src/token_hunt_pro/cli.py tests/test_store_license.py tests/test_cli_activate.py
git commit -m "license: activate + status commands with on-disk store"
```

---

## Phase 2: First Pro Features (Tasks 5-6)

### Task 5: Silent redaction via PostToolUse hook integration

**Files:**
- Create: `src/token_hunt_pro/redact.py`
- Modify: `src/token_hunt_pro/cli.py` (add `redact` subcommand)
- Create: `tests/test_redact.py`
- Create: `tests/test_cli_redact.py`
- Modify (free repo): `E:/dev/projects/token-hunt/plugin/hooks/post-bash.sh`
- Modify (free repo): `E:/dev/projects/token-hunt/plugin/hooks/post-read.sh`
- Modify (free repo): `E:/dev/projects/token-hunt/plugin/hooks/post-write.sh`

- [ ] **Step 1: Write `tests/test_redact.py` (TDD)**

```python
import pytest

from token_hunt_pro.redact import redact_text, _redact_value
from tests.fixtures import ZAI_KEY, ANTHROPIC_KEY  # assumes token-hunt's fixtures importable


def test_redact_value_replaces_with_placeholder():
    redacted = _redact_value("sk-ant-test123", kind="anthropic-key", fingerprint="abc123def456")
    assert "sk-ant-test123" not in redacted
    assert "[REDACTED:anthropic-key:abc123def456]" in redacted


def test_redact_text_replaces_zai_key():
    text = f"my key is {ZAI_KEY} please help"
    from token_hunt.regex_scanner import _fingerprint
    redacted = redact_text(text, detection_point="PostToolUse:Bash")
    assert ZAI_KEY not in redacted
    fp = _fingerprint(ZAI_KEY)
    assert f"[REDACTED:zai-api-key:{fp}]" in redacted


def test_redact_text_handles_no_secrets():
    text = "just a normal sentence"
    assert redact_text(text, detection_point="PostToolUse:Bash") == text


def test_redact_text_handles_multiple_secrets():
    text = f"{ZAI_KEY} {ANTHROPIC_KEY}"
    redacted = redact_text(text, detection_point="PostToolUse:Bash")
    assert ZAI_KEY not in redacted
    assert ANTHROPIC_KEY not in redacted


def test_redact_text_preserves_surrounding_context():
    text = f"line1\nsecret={ZAI_KEY}\nline3"
    redacted = redact_text(text, detection_point="PostToolUse:Bash")
    assert "line1" in redacted
    assert "line3" in redacted
    assert "secret=[REDACTED" in redacted


def test_redact_text_requires_no_active_license(tmp_home, monkeypatch):
    """Without a stored license, redaction refuses to run (returns text unchanged + signals)."""
    from token_hunt_pro.store_license import load_stored_license
    # No license.json present
    assert load_stored_license() is None
    text = f"key={ZAI_KEY}"
    result = redact_text(text, detection_point="PostToolUse:Bash")
    # Without license, NO redaction — returns text as-is
    assert result == text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_redact.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Write `src/token_hunt_pro/redact.py`**

```python
from __future__ import annotations

from token_hunt.engine import scan as _scan_engine
from token_hunt.regex_scanner import _fingerprint
from token_hunt.types import ScanContext
from token_hunt_pro.store_license import load_stored_license


def _redact_value(value: str, kind: str, fingerprint: str) -> str:
    """Replace a secret value with a stable placeholder."""
    if fingerprint:
        return f"[REDACTED:{kind}:{fingerprint}]"
    # No fingerprint (e.g. entropy candidate) — use value hash for stable replace
    return f"[REDACTED:{kind}:{_fingerprint(value)}]"


def redact_text(text: str, detection_point: str) -> str:
    """Scan text and replace every detected secret with a stable placeholder.

    License-gated: returns text unchanged if no valid Pro license is stored.
    This prevents free users from getting the silent-redaction behavior even
    if they install the pro package without paying.
    """
    if load_stored_license() is None:
        return text

    ctx = ScanContext(detection_point=detection_point)
    result = _scan_engine(text, ctx)
    if not result.matches:
        return text

    redacted = text
    # Replace longest values first so substring matches don't break longer ones
    for match in sorted(result.matches, key=lambda m: -len(m.value)):
        placeholder = _redact_value(match.value, match.kind, match.fingerprint)
        redacted = redacted.replace(match.value, placeholder)
    return redacted
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -m pytest tests/test_redact.py -v`
Expected: 6 passed.

- [ ] **Step 5: Add `redact` subcommand to `src/token_hunt_pro/cli.py`**

Append to existing `cli.py` (do not replace existing `activate` / `status` commands):

```python
@main.command()
@click.option("--stdin", is_flag=True, help="Read text from stdin.")
@click.option("--context", default="PostToolUse:Read",
              help="Detection point (e.g. PostToolUse:Bash, PostToolUse:Read).")
def redact(stdin, context):
    """Read text, output redacted version. Used by PostToolUse hooks."""
    import sys
    from token_hunt_pro.redact import redact_text
    from token_hunt_pro.store_license import load_stored_license

    if load_stored_license() is None:
        click.echo("error: no active license. Run: token-hunt-pro activate <key>", err=True)
        sys.exit(2)

    if not stdin:
        click.echo("error: --stdin required (no file mode yet)", err=True)
        sys.exit(2)

    text = sys.stdin.read()
    sys.stdout.write(redact_text(text, detection_point=context))
```

- [ ] **Step 6: Write `tests/test_cli_redact.py`**

```python
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from token_hunt_pro.cli import main
from token_hunt_pro.types import License, Tier
from token_hunt_pro.store_license import save_validated_license
from tests.fixtures import ZAI_KEY


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def active_license(tmp_home):
    save_validated_license(License(
        tier=Tier.SOLO, customer_email="x@y.z", customer_id="c",
        issued_at=datetime.now(timezone.utc) - timedelta(days=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    ))


def test_redact_without_license_errors(runner, tmp_home):
    # No license active
    result = runner.invoke(main, ["redact", "--stdin"], input=f"key={ZAI_KEY}")
    assert result.exit_code == 2
    assert "no active license" in result.output.lower()


def test_redact_with_license_outputs_redacted_text(runner, active_license):
    result = runner.invoke(main, ["redact", "--stdin"], input=f"key={ZAI_KEY}")
    assert result.exit_code == 0
    assert ZAI_KEY not in result.output
    assert "[REDACTED:" in result.output


def test_redact_clean_text_passes_through(runner, active_license):
    result = runner.invoke(main, ["redact", "--stdin"], input="hello world")
    assert result.exit_code == 0
    assert result.output == "hello world"
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli_redact.py -v`
Expected: 3 passed.

- [ ] **Step 8: Update free-repo PostToolUse hooks to delegate to Pro**

In `E:/dev/projects/token-hunt/plugin/hooks/post-bash.sh`, replace the WARN block with a Pro-delegation check. Insert BEFORE the existing token-hunt scan call, after the `command -v` check:

```bash
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
```

Apply the same edit to `post-read.sh` (use context `PostToolUse:Read` and variable `$content` instead of `$stdout`) and `post-write.sh` (use context `PostToolUse:Write`).

- [ ] **Step 9: Run free-repo tests to verify hooks still work**

```bash
cd /e/dev/projects/token-hunt
py -m pytest tests/test_hook_post_bash.py tests/test_hook_post_read.py tests/test_hook_pre_write.py -v
```
Expected: all pass (Pro delegation is silent no-op when Pro not installed).

- [ ] **Step 10: Commit (Pro repo)**

```bash
cd /e/dev/projects/token-hunt-pro
git add src/token_hunt_pro/redact.py src/token_hunt_pro/cli.py tests/test_redact.py tests/test_cli_redact.py
git commit -m "feat: silent redaction via redact_text + redact CLI subcommand"
```

- [ ] **Step 11: Commit (free repo)**

```bash
cd /e/dev/projects/token-hunt
git add plugin/hooks/post-bash.sh plugin/hooks/post-read.sh plugin/hooks/post-write.sh
git commit -m "plugin: PostToolUse hooks delegate to token-hunt-pro redact when license active"
```

---

### Task 6: Active verification (GitHub, Stripe, Slack)

**Files:**
- Create: `src/token_hunt_pro/verifiers/__init__.py`
- Create: `src/token_hunt_pro/verifiers/github.py`
- Create: `src/token_hunt_pro/verifiers/stripe.py`
- Create: `src/token_hunt_pro/verifiers/slack.py`
- Modify: `src/token_hunt_pro/cli.py` (add `verify` subcommand)
- Create: `tests/test_verifiers.py`
- Create: `tests/test_cli_verify.py`

- [ ] **Step 1: Write `tests/test_verifiers.py` (TDD with responses library)**

```python
import pytest
import responses

from token_hunt_pro.verifiers import verify_secret, VerificationResult
from token_hunt_pro.verifiers.github import verify_github
from token_hunt_pro.verifiers.stripe import verify_stripe
from token_hunt_pro.verifiers.slack import verify_slack


@responses.activate
def test_verify_github_returns_valid_for_200():
    responses.add(
        responses.GET,
        "https://api.github.com/user",
        json={"login": "testuser", "id": 12345},
        status=200,
    )
    result = verify_github("ghp_validtoken123")
    assert result.is_live is True
    assert "testuser" in result.detail


@responses.activate
def test_verify_github_returns_invalid_for_401():
    responses.add(
        responses.GET,
        "https://api.github.com/user",
        json={"message": "Bad credentials"},
        status=401,
    )
    result = verify_github("ghp_invalidtoken")
    assert result.is_live is False


@responses.activate
def test_verify_stripe_returns_valid_for_200():
    responses.add(
        responses.GET,
        "https://api.stripe.com/v1/account",
        json={"id": "acct_123", "display_name": "TestCo"},
        status=200,
    )
    result = verify_stripe("sk_live_valid")
    assert result.is_live is True


@responses.activate
def test_verify_slack_returns_valid_for_ok_true():
    responses.add(
        responses.POST,
        "https://slack.com/api/auth.test",
        json={"ok": True, "user": "testbot", "team": "TestTeam"},
        status=200,
    )
    result = verify_slack("xoxb-validtoken")
    assert result.is_live is True


@responses.activate
def test_verify_slack_returns_invalid_for_ok_false():
    responses.add(
        responses.POST,
        "https://slack.com/api/auth.test",
        json={"ok": False, "error": "invalid_auth"},
        status=200,
    )
    result = verify_slack("xoxb-invalid")
    assert result.is_live is False


def test_verify_secret_dispatches_to_correct_verifier():
    """Given a kind, dispatches to the right provider verifier."""
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.github.com/user",
            json={"login": "testuser"},
            status=200,
        )
        result = verify_secret("github-pat", "ghp_validtoken123")
        assert result.is_live is True


def test_verify_secret_returns_unknown_for_unsupported_provider():
    result = verify_secret("zai-api-key", "anything")
    assert result.is_live is None  # None = unknown / unsupported
    assert "no active verifier" in result.detail.lower() or "unsupported" in result.detail.lower()


@responses.activate
def test_verify_handles_network_error_gracefully():
    import httpx
    responses.add(
        responses.GET,
        "https://api.github.com/user",
        body=httpx.ConnectError("simulated network failure"),
    )
    result = verify_github("ghp_anytoken")
    assert result.is_live is None  # None = could not determine
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -m pytest tests/test_verifiers.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Write `src/token_hunt_pro/verifiers/__init__.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

import httpx

from token_hunt_pro.verifiers.github import verify_github
from token_hunt_pro.verifiers.stripe import verify_stripe
from token_hunt_pro.verifiers.slack import verify_slack


@dataclass(frozen=True)
class VerificationResult:
    """Result of an active-verification check.

    is_live meanings:
        True  = the secret is live (provider confirmed authentication)
        False = the secret is dead (provider rejected authentication)
        None  = could not determine (network error, unsupported provider, etc.)
    """
    is_live: Optional[bool]
    detail: str
    provider: str


# Dispatch table: rule kind → verifier function
VERIFIERS = {
    "github-pat": lambda v: verify_github(v),
    "github-fine-pat": lambda v: verify_github(v),
    "stripe-sk": lambda v: verify_stripe(v),
    "slack-token": lambda v: verify_slack(v),
}


def verify_secret(kind: str, value: str, timeout: float = 5.0) -> VerificationResult:
    """Verify a secret against its provider's API.

    Returns VerificationResult with is_live True/False/None.
    Never raises — network/parse errors map to is_live=None.
    """
    verifier = VERIFIERS.get(kind)
    if verifier is None:
        return VerificationResult(
            is_live=None,
            detail=f"no active verifier for kind '{kind}'",
            provider=kind,
        )
    try:
        return verifier(value, timeout=timeout)
    except httpx.HTTPError as e:
        return VerificationResult(
            is_live=None,
            detail=f"network error: {type(e).__name__}",
            provider=kind,
        )
    except Exception as e:
        return VerificationResult(
            is_live=None,
            detail=f"unexpected error: {type(e).__name__}: {e}",
            provider=kind,
        )
```

- [ ] **Step 4: Write `src/token_hunt_pro/verifiers/github.py`**

```python
from __future__ import annotations
import httpx

from token_hunt_pro.verifiers import VerificationResult


def verify_github(token: str, timeout: float = 5.0) -> VerificationResult:
    """Check if a GitHub PAT is live by calling GET /user."""
    try:
        resp = httpx.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "token-hunt-pro/0.2",
            },
            timeout=timeout,
        )
    except httpx.HTTPError as e:
        return VerificationResult(
            is_live=None, detail=f"network error: {type(e).__name__}", provider="github-pat"
        )

    if resp.status_code == 200:
        login = resp.json().get("login", "unknown")
        return VerificationResult(
            is_live=True, detail=f"authenticated as {login}", provider="github-pat"
        )
    if resp.status_code in (401, 403):
        return VerificationResult(
            is_live=False, detail=f"rejected (HTTP {resp.status_code})", provider="github-pat"
        )
    return VerificationResult(
        is_live=None, detail=f"unexpected HTTP {resp.status_code}", provider="github-pat"
    )
```

- [ ] **Step 5: Write `src/token_hunt_pro/verifiers/stripe.py`**

```python
from __future__ import annotations
import httpx

from token_hunt_pro.verifiers import VerificationResult


def verify_stripe(key: str, timeout: float = 5.0) -> VerificationResult:
    """Check if a Stripe secret key is live by calling GET /v1/account."""
    try:
        resp = httpx.get(
            "https://api.stripe.com/v1/account",
            auth=(key, ""),  # Stripe uses HTTP Basic with key as username
            timeout=timeout,
        )
    except httpx.HTTPError as e:
        return VerificationResult(
            is_live=None, detail=f"network error: {type(e).__name__}", provider="stripe-sk"
        )

    if resp.status_code == 200:
        account = resp.json()
        name = account.get("display_name") or account.get("id", "unknown")
        return VerificationResult(
            is_live=True, detail=f"account: {name}", provider="stripe-sk"
        )
    if resp.status_code in (401, 403):
        return VerificationResult(
            is_live=False, detail=f"rejected (HTTP {resp.status_code})", provider="stripe-sk"
        )
    return VerificationResult(
        is_live=None, detail=f"unexpected HTTP {resp.status_code}", provider="stripe-sk"
    )
```

- [ ] **Step 6: Write `src/token_hunt_pro/verifiers/slack.py`**

```python
from __future__ import annotations
import httpx

from token_hunt_pro.verifiers import VerificationResult


def verify_slack(token: str, timeout: float = 5.0) -> VerificationResult:
    """Check if a Slack token is live by calling auth.test."""
    try:
        resp = httpx.post(
            "https://slack.com/api/auth.test",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "token-hunt-pro/0.2",
            },
            timeout=timeout,
        )
    except httpx.HTTPError as e:
        return VerificationResult(
            is_live=None, detail=f"network error: {type(e).__name__}", provider="slack-token"
        )

    if resp.status_code != 200:
        return VerificationResult(
            is_live=None, detail=f"unexpected HTTP {resp.status_code}", provider="slack-token"
        )

    body = resp.json()
    if body.get("ok") is True:
        user = body.get("user", "unknown")
        team = body.get("team", "unknown")
        return VerificationResult(
            is_live=True, detail=f"{user} @ {team}", provider="slack-token"
        )
    error = body.get("error", "unknown")
    return VerificationResult(
        is_live=False, detail=f"rejected: {error}", provider="slack-token"
    )
```

- [ ] **Step 7: Run verifier tests to verify they pass**

Run: `py -m pytest tests/test_verifiers.py -v`
Expected: 8 passed.

- [ ] **Step 8: Add `verify` subcommand to `src/token_hunt_pro/cli.py`**

Append (do not replace existing commands):

```python
@main.command()
@click.argument("kind")
@click.option("--stdin", is_flag=True, help="Read secret value from stdin.")
@click.argument("value", required=False)
def verify(kind, stdin, value):
    """Verify if a secret is live by calling its provider's API.

    KIND is the rule kind (e.g. github-pat, stripe-sk, slack-token).

    Examples:
        token-hunt-pro verify github-pat ghp_abc123...
        echo "ghp_abc123..." | token-hunt-pro verify github-pat --stdin
    """
    import sys
    from token_hunt_pro.verifiers import verify_secret
    from token_hunt_pro.store_license import load_stored_license

    if load_stored_license() is None:
        click.echo("error: no active license. Run: token-hunt-pro activate <key>", err=True)
        sys.exit(2)

    if stdin:
        secret_value = sys.stdin.read().strip()
    elif value:
        secret_value = value
    else:
        click.echo("error: provide a VALUE or use --stdin", err=True)
        sys.exit(2)

    result = verify_secret(kind, secret_value)
    label = {True: "LIVE", False: "DEAD", None: "UNKNOWN"}[result.is_live]
    click.echo(f"{kind}: {label}")
    click.echo(f"  detail: {result.detail}")
    sys.exit({True: 0, False: 1, None: 2}[result.is_live])
```

- [ ] **Step 9: Write `tests/test_cli_verify.py`**

```python
from datetime import datetime, timedelta, timezone

import pytest
import responses
from click.testing import CliRunner

from token_hunt_pro.cli import main
from token_hunt_pro.store_license import save_validated_license
from token_hunt_pro.types import License, Tier


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def active_license(tmp_home):
    save_validated_license(License(
        tier=Tier.SOLO, customer_email="x@y.z", customer_id="c",
        issued_at=datetime.now(timezone.utc) - timedelta(days=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    ))


def test_verify_without_license_fails(runner, tmp_home):
    result = runner.invoke(main, ["verify", "github-pat", "ghp_anything"])
    assert result.exit_code == 2


@responses.activate
def test_verify_live_secret_returns_zero(runner, active_license):
    responses.add(
        responses.GET, "https://api.github.com/user",
        json={"login": "testuser"}, status=200,
    )
    result = runner.invoke(main, ["verify", "github-pat", "ghp_live"])
    assert result.exit_code == 0
    assert "LIVE" in result.output


@responses.activate
def test_verify_dead_secret_returns_one(runner, active_license):
    responses.add(
        responses.GET, "https://api.github.com/user",
        json={"message": "Bad credentials"}, status=401,
    )
    result = runner.invoke(main, ["verify", "github-pat", "ghp_dead"])
    assert result.exit_code == 1
    assert "DEAD" in result.output


def test_verify_unsupported_kind_returns_two(runner, active_license):
    result = runner.invoke(main, ["verify", "zai-api-key", "anything"])
    assert result.exit_code == 2
    assert "UNKNOWN" in result.output
```

- [ ] **Step 10: Run tests to verify they pass**

Run: `py -m pytest tests/test_cli_verify.py -v`
Expected: 4 passed.

- [ ] **Step 11: Run full test suite**

Run: `py -m pytest -v`
Expected: all tests pass.

- [ ] **Step 12: Commit**

```bash
git add src/token_hunt_pro/verifiers/ src/token_hunt_pro/cli.py tests/test_verifiers.py tests/test_cli_verify.py
git commit -m "feat: active verification for GitHub, Stripe, Slack"
```

---

### Task 7: Smoke-test the full Pro flow + Pro-repo CHANGELOG

**Files:**
- Create: `CHANGELOG.md`
- Create: `SECURITY.md`
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to token-hunt-pro are documented here.

## [0.2.0] — 2026-07-XX

### Added
- Initial commercial release.
- License validation: ed25519-signed license keys, offline verification.
- `token-hunt-pro activate <key>` command stores license to `~/.token-hunt/license.json`.
- `token-hunt-pro status` shows current license tier + expiry.
- Silent redaction via `token-hunt-pro redact --stdin`. Free token-hunt PostToolUse hooks auto-delegate when license is active.
- Active verification for GitHub (PAT), Stripe (secret key), Slack (bot/user/app tokens) via `token-hunt-pro verify <kind> [value]`.

### License
Commercial. Source-available to paying customers. See `LICENSE-PRO`.
```

- [ ] **Step 2: Write `SECURITY.md`**

```markdown
# Security Policy

## Reporting a Vulnerability

Email **security@jordannewell.com** with details and repro steps.

**Acknowledgment SLA: 72 hours.**

## License Key Security

License keys are ed25519-signed by a master private key held offline by the maintainer. The public key ships with the package at `src/token_hunt_pro/keys/license_pubkey.pem`.

If the master private key is compromised, ALL issued licenses must be rotated. The maintainer will:
1. Publish a new package version with a new public key
2. Re-issue licenses to all active customers
3. Reject all keys signed by the compromised private key

## Active Verification Safety

`token-hunt-pro verify <kind>` sends the secret value to the provider's API to check if it's live. This is by design — but it means the secret traverses HTTPS to its own provider. The verification ONLY contacts the legitimate provider domain (api.github.com, api.stripe.com, slack.com); no third-party services are involved.

If you do not want token-hunt-pro to make outbound API calls for verification, do not run the `verify` subcommand. The `redact` subcommand is fully local and makes zero network calls.
```

- [ ] **Step 3: Write `.github/workflows/test.yml`**

```yaml
name: test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e402052b7b6f6d  # v5
        with:
          python-version: ${{ matrix.python-version }}
      # Free token-hunt must be installed first (Pro depends on it)
      - run: pip install git+https://github.com/JordanNewell/token-hunt.git
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: pytest --cov=token_hunt_pro --cov-report=xml
```

- [ ] **Step 4: Run full smoke test locally**

Run:
```bash
cd /e/dev/projects/token-hunt-pro
py -m pytest -v --tb=short
```
Expected: all tests pass.

- [ ] **Step 5: Manual end-to-end smoke test**

Run:
```bash
# Activate with a freshly-signed key (Jordan generates this with scripts/sign_license.py — Phase 3)
# For now: skip activation, test the no-license paths:
token-hunt-pro status
# Expected: "no license active"

echo "garbage" | token-hunt-pro redact --stdin
# Expected: error, exit 2 — no active license

token-hunt-pro verify github-pat ghp_anything
# Expected: error, exit 2 — no active license
```

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md SECURITY.md .github/workflows/test.yml
git commit -m "ship: v0.2.0 changelog, security policy, CI workflow"
```

---

## Phase 3-4 Operational Checklist (NOT an implementation plan — Jordan's manual setup)

After Tasks 1-7 ship, the following external-services work happens OUT OF BAND. Save as `docs/superpowers/plans/2026-07-27-token-hunt-pro-v0.2-gtm.md` (a checklist, not TDD-able tasks):

### Operational tasks (Jordan's setup work)

- [ ] **Stripe account + product setup**
  - Create Stripe account at stripe.com
  - Create 3 products: Solo Pro ($8/mo), Team Pro ($5/user/mo with min 5 users), Enterprise (contact sales)
  - Get test + live API keys
  - Build checkout session via Stripe Checkout (no custom UI needed)

- [ ] **License server (Supabase)**
  - Create Supabase project
  - Schema: `licenses(id, customer_email, tier, seats, stripe_customer_id, issued_at, expires_at, status)`
  - Row-level security: customers can read their own row only
  - Generate ed25519 signed license key on row insert via edge function

- [ ] **Stripe webhook → license generation**
  - Endpoint that receives `checkout.session.completed` events
  - Inserts license row in Supabase
  - Generates signed license key using `master_private_key.pem`
  - Emails customer via Resend/Postmark

- [ ] **Email delivery**
  - Create Resend account (free 100/day)
  - Domain verify `jordannewell.com`
  - Template: "Your token-hunt Pro license" with key + install instructions

- [ ] **PyPI publication (private package)**
  - Build wheel: `py -m build`
  - Upload to PyPI: `twine upload dist/*`
  - Package is public on PyPI (the LICENSE-PRO forbids redistribution, enforcement is legal not technical)

- [ ] **GitHub repo setup**
  - Create `JordanNewell/token-hunt-pro` as **PRIVATE** repo
  - Invite paying customers as read-only collaborators (source-access)
  - Tag `v0.2.0`, push

- [ ] **Landing page**
  - Create `src/content/products/token-hunt-pro.md` on jordannewell.com
  - Pricing tiers, install instructions, "Buy Pro" → Stripe Checkout links
  - Deploy via existing `bash scripts/deploy.sh`

- [ ] **Launch material**
  - Show HN post (template in Phase 4 of spec)
  - r/netsec post (text-only, technical framing)
  - dev.to writeup
  - X thread

- [ ] **First-customer manual fallback**
  - `scripts/sign_license.py` (Jordan's local script — never in repo)
  - Reads customer_email + tier from Stripe dashboard manually
  - Generates signed key with `master_private_key.pem`
  - Emails via Resend CLI
  - Used while webhook automation is being built

---

## Self-Review

**Spec coverage check:**
- License validation (offline ed25519): ✓ Tasks 2-4
- Silent redaction via updatedToolOutput: ✓ Task 5
- Active verification (GitHub/Stripe/Slack): ✓ Task 6 (3 of 12 providers — Anthropic, OpenAI, others deferred to v0.2.1)
- Auto-rotation API: **DEFERRED** to v0.3 — most providers don't have rotation APIs; what we'd build is browser-open + .env-update which requires a secrets vault feature not yet designed
- Fleet sync: DEFERRED to v0.3 (per spec)
- Dashboard: DEFERRED to v0.3 (per spec)
- Billing/delivery: ✓ Operational checklist (Phase 3)
- Distribution: ✓ Operational checklist (Phase 4)

**Placeholder scan:** No TBDs. Operational checklist items reference real services (Stripe, Supabase, Resend) but don't claim they're built — they're Jordan's manual setup.

**Type consistency:** License dataclass fields (tier, customer_email, customer_id, issued_at, expires_at, seats) used consistently across codec, validator, store, and CLI. VerificationResult dataclass fields (is_live, detail, provider) consistent across dispatch + 3 verifiers.

**Scope check:** Plan covers Tasks 1-7 (code-only, TDD-able, ~10 days of work). Phase 3-4 is operational, requires Jordan's external accounts. Plan produces working software on its own: a fully-functional `token-hunt-pro` package installable from source with all 4 CLI commands (activate, status, redact, verify). Revenue generation requires the Phase 3-4 operational checklist completion.

**Open items for refinement:**
- Task 5's monkeypatch approach for `_PUBKEY_PATH` is test-only; production ships with the real public key embedded in package
- Task 6's verifiers contact real provider APIs in production; tests use `responses` library to mock
- Task 7 expects `scripts/sign_license.py` to exist for manual license generation — this is in Phase 3 operational checklist (Jordan's local tool, never in repo)
