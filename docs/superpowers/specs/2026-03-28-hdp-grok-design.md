# hdp-grok Design Spec

**Date:** 2026-03-28
**Branch:** feat/hdp-grok
**Package:** `hdp-grok` → PyPI
**Tag convention:** `python/hdp-grok/v*`

---

## Overview

`hdp-grok` is a fully standalone Python package that brings Human Delegation Provenance (HDP) to Grok (xAI API) and any OpenAI-compatible client. It provides:

1. **Tool JSON schemas** (`HDP_TOOLS`) ready to pass to `tools=` in xAI / OpenAI calls
2. **Stateful `HdpMiddleware`** that manages session state, signs tokens, and routes Grok tool calls by name

No dependency on `hdp-crewai` or any AI framework. Runtime deps: `cryptography>=42.0.0`, `jcs>=0.2.1`.

---

## Package Structure

```
packages/hdp-grok/
├── src/hdp_grok/
│   ├── __init__.py        # public API surface
│   ├── _crypto.py         # standalone Ed25519 sign/verify + RFC 8785 canonical JSON
│   │                      # exposes: issue_root_token(), extend_token_chain(),
│   │                      #          verify_token_with_key()
│   ├── _types.py          # slim HDP types (no CrewAI or framework deps)
│   ├── tools.py           # HDP_TOOLS list + get_hdp_tools()
│   └── middleware.py      # HdpMiddleware class
├── examples/
│   └── grok_with_hdp.py   # minimal working xAI SDK example
├── tests/
│   └── test_middleware.py
├── pyproject.toml
└── .releaseguard.yml
```

---

## Crypto Layer (`_crypto.py`)

Standalone copy of the Ed25519 + RFC 8785 signing scheme used in `hdp-crewai`. Same wire
format — tokens produced by `hdp-grok` are verifiable by the TypeScript SDK and vice versa.

All imports inside `HdpMiddleware` are **internal only**:
```python
from ._crypto import issue_root_token, extend_token_chain, verify_token_with_key
```

### Wire format for `scope`

The root token `scope` field is a dict matching the established HDP wire format (compatible
with the TypeScript SDK). `_crypto.py` constructs it as:

```python
{
    "intent": principal_id,          # human-readable delegation intent
    "data_classification": "internal",
    "network_egress": True,
    "persistence": False,
    "authorized_tools": scope,       # list[str] passed by caller, may be []
}
```

This matches `ScopePolicy.to_dict()` in `hdp-crewai` and the TypeScript `HdpScope` type.

### `issue_root_token(signing_key, key_id, session_id, principal_id, scope, expires_in) -> dict`

Builds and signs the root HDP token dict:
- `header`: `token_id` (UUID v4), `issued_at` (ms), `expires_at` (ms), `session_id`, `version="0.1"`
- `principal`: `id=principal_id`, `id_type="opaque"`
- `scope`: dict as described above
- `chain`: `[]`
- `signature`: Ed25519 over RFC 8785 canonical JSON of `{header, principal, scope}`

Signature dict: `{"alg": "Ed25519", "kid": key_id, "value": <base64url>, "signed_fields": ["header", "principal", "scope"]}`

### `extend_token_chain(parent_token, signing_key, key_id, delegatee_id, additional_scope) -> dict`

Appends a signed hop to the existing chain and returns the updated token dict.

Hop fields (unsigned portion):
```python
{
    "seq": hop_seq,                    # 1-based, increments per hop
    "agent_id": delegatee_id,
    "agent_type": "sub-agent",
    "timestamp": int(time.time() * 1000),
    "action_summary": "",              # empty string for Grok hops (no step output available)
    "parent_hop": hop_seq - 1,
}
```

Hop signature payload — **cumulative chain semantics**:
- The list passed to the signing payload is `chain[:i] + [current_unsigned_hop]`
- **Prior hops in this list retain their `hop_signature` fields** — only the current hop being signed has no `hop_signature` yet
- Signed over: RFC 8785 canonical `{"chain": cumulative_list, "root_sig": token["signature"]["value"]}`
- `hop_signature`: base64url-encoded Ed25519 signature bytes (string, stored on the hop dict)

This matches the signing scheme in `hdp-crewai/_crypto.py` `sign_hop()`.

### `verify_token_with_key(token_str, public_key_bytes) -> dict`

Ed25519 signature verification requires the signer's public key — it cannot be derived from
the token itself. This function takes the raw 32-byte public key alongside the token string.

Verifies:
1. Root signature over RFC 8785 canonical `{header, principal, scope}`
2. Each hop signature over its cumulative chain (same semantics as signing above)
3. Token expiry (`expires_at` vs `time.time() * 1000`)

Returns:
```python
{
    "valid":        bool,
    "hop_count":    int,
    "principal_id": str | None,
    "session_id":   str | None,
    "expires_at":   int,           # unix timestamp ms
    "expired":      bool,
    "violations":   list[str],     # scope_violations recorded in token extensions
    "chain":        list[dict],    # full hop list from token
}
```

`HdpMiddleware.verify_token(token_str)` calls this internally, passing the public key
derived from `self.signing_key` via `Ed25519PrivateKey.from_private_bytes(...).public_key()`.

---

## Middleware (`middleware.py`)

### Errors

```python
class HdpSigningKeyError(Exception):
    """No signing key provided and HDP_SIGNING_KEY env var is absent."""

class HdpTokenMissingError(Exception):
    """extend_chain called before issue_token."""

class HdpTokenExpiredError(Exception):
    """Current token's expires_at has passed."""
```

### `HdpMiddleware`

```python
class HdpMiddleware:
    def __init__(
        self,
        signing_key: bytes | str | None = None,
        # Accepts:
        #   bytes  — raw 32-byte Ed25519 private key
        #   str    — base64url or hex (with or without 0x prefix)
        #   None   — reads HDP_SIGNING_KEY env var (base64url)
        # Raises HdpSigningKeyError if none resolves.
        key_id: str = "default",
        default_expires_in: int = 3600,       # seconds
        session_id: str | None = None,        # auto UUID v4 if None
        principal_id: str | None = None,      # used in issue_token
    ) -> None
```

Key normalisation order in `__init__`:
1. If `None` → read `HDP_SIGNING_KEY` env var (expected: base64url) → raise `HdpSigningKeyError` if absent
2. If `str` starting with `"0x"` → `bytes.fromhex(s[2:])`
3. If `str` → try base64url decode (with padding tolerance) → fallback to hex decode

Derives and stores `self._public_key_bytes` from the resolved signing key at init time
(used by `verify_token` without re-derivation on every call).

### Token lifecycle methods

```python
def issue_token(
    self,
    scope: list[str] | None = None,
    expires_in: int | None = None,    # overrides default_expires_in
) -> dict:
    """Returns {"token": "<json_string>"}"""
    # Raises ValueError if principal_id was not set at init

def extend_chain(
    self,
    delegatee_id: str,
    additional_scope: list[str] | None = None,
) -> dict:
    """Returns {"new_token": "<json_string>"}"""
    # Raises HdpTokenMissingError if no current token
    # Raises HdpTokenExpiredError if expires_at has passed

def verify_token(self, token: str) -> dict:
    """Verifies token using derived public key. Returns:
    {
        "valid":        bool,
        "hop_count":    int,
        "principal_id": str | None,
        "session_id":   str | None,
        "expires_at":   int,       # unix timestamp ms
        "expired":      bool,
        "violations":   list[str],
        "chain":        list[dict],
    }
    """

def reset(self) -> None:
    """Clears _current_token and _hop_count. Keeps session_id and principal_id."""
```

### Dispatch

```python
def handle_tool_call(self, name: str, args: dict) -> dict:
    """Routes hdp_issue_token | hdp_extend_chain | hdp_verify_token.
    Handles both snake_case and camelCase arg names from Grok.
    Raises ValueError for unrecognised tool names with a clear message listing supported names."""
```

camelCase normalisation handled in `handle_tool_call`:
- `delegateeId` → `delegatee_id`
- `additionalScope` → `additional_scope`

### Inspection

```python
def export_current_token(self) -> dict | None:
    """Live in-memory token dict, or None before issue_token."""

def __repr__(self) -> str:
    # "HdpMiddleware(session_id='abc-123', hops=2, valid=True)"
```

---

## Tools (`tools.py`)

Three tool schemas in OpenAI-compatible format. No `session_id`/`principal_id` in
`hdp_issue_token` — those are held by the middleware instance:

| Tool | Required args | Optional args |
|---|---|---|
| `hdp_issue_token` | — | `scope[]`, `expires_in` |
| `hdp_extend_chain` | `delegatee_id` | `additional_scope[]` |
| `hdp_verify_token` | `token` | — |

```python
HDP_TOOLS: list[dict]           # pass directly to tools= parameter
def get_hdp_tools() -> list[dict]
```

---

## Public API (`__init__.py`)

```python
from hdp_grok import (
    HdpMiddleware,
    HdpSigningKeyError,
    HdpTokenMissingError,
    HdpTokenExpiredError,
    HDP_TOOLS,
    get_hdp_tools,
)
```

---

## Release Pipeline

### `on.push.tags` block in `release.yml`

Three patterns required (third is new):

```yaml
on:
  push:
    tags:
      - 'v*'
      - 'python/v*'
      - 'python/hdp-grok/v*'    # ← new — without this the pipeline never fires
```

The existing hdp-crewai guard `if: startsWith(github.ref, 'refs/tags/python/v')` is safe —
`python/hdp-grok/v*` does NOT match `refs/tags/python/v` (the infix `hdp-grok/` prevents it).

### New jobs in `release.yml`

```
test-hdp-grok
  if: startsWith(github.ref, 'refs/tags/python/hdp-grok/v')
  runs-on: ubuntu-latest
  steps: checkout → setup-python 3.12 → pip install -e ".[dev]" → pytest tests/ -v
    ↓
vet-hdp-grok
  needs: test-hdp-grok
  steps: checkout → setup-python 3.12 → pip install build → python -m build
       → ReleaseGuard (pinned SHA: 94c067008f3ad516d4b61a6e7163d9d5518a4548)
         artifact-name: releaseguard-evidence-hdp-grok
       → upload artifact: hdp-grok-dist (retention-days: 1)
    ↓
publish-hdp-grok
  needs: vet-hdp-grok
  permissions: contents: read, id-token: write
  environment: pypi-hdp-grok
  steps: download hdp-grok-dist → pypa/gh-action-pypi-publish@release/v1
```

### `packages/hdp-grok/.releaseguard.yml`

Mirrors `packages/hdp-crewai/.releaseguard.yml` exactly:

```yaml
version: 2
project:
  name: hdp-grok
  mode: release
inputs:
  - path: ./dist
    type: directory
sbom:
  enabled: true
  ecosystems: [python]
  formats: [cyclonedx]
  enrich_cve: false
scanning:
  secrets:
    enabled: true
  metadata:
    enabled: true
    fail_on_source_maps: false
    fail_on_internal_urls: false
    fail_on_build_paths: false
  unexpected_files:
    enabled: true
    deny: [".env", "*.bak", "*.tmp", "*.key", "*.pem"]
  licenses:
    enabled: true
    require:
      - LICENSE
transforms:
  add_checksums: false
  add_manifest: false
policy:
  fail_on:
    - severity: critical
    - category: secret
  warn_on:
    - severity: high
output:
  reports: [cli, sarif]
  directory: ./.releaseguard
```

### CI (`ci.yml`)

New `test-hdp-grok` matrix job (Python 3.10 / 3.11 / 3.12) runs on every push/PR.

---

## `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hdp-grok"
version = "0.1.0"
description = "HDP (Human Delegation Provenance) middleware for Grok / xAI API"
license = { text = "CC-BY-4.0" }
requires-python = ">=3.10"
dependencies = [
    "cryptography>=42.0.0",
    "jcs>=0.2.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]

[tool.hatch.build.targets.wheel]
packages = ["src/hdp_grok"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

---

## Testing

`tests/test_middleware.py` covers:

**Key normalisation**
- bytes input → accepted
- base64url str input → decoded correctly
- hex str input → decoded correctly
- `0x`-prefixed hex str → decoded correctly
- `None` + `HDP_SIGNING_KEY` env var set → accepted
- `None` + no env var → raises `HdpSigningKeyError`

**`issue_token`**
- Happy path — token is a valid JSON string, root signature verifies with public key
- `principal_id` not set at init → raises `ValueError`
- Second call rotates token (new `token_id`, `_hop_count` reset to 0)

**`extend_chain`**
- Happy path — hop appended, `_hop_count` incremented, hop signature verifies
- Called before `issue_token` → raises `HdpTokenMissingError`
- Called on expired token → raises `HdpTokenExpiredError`

**`verify_token`**
- Fresh token → `valid=True`, `hop_count=0`
- Token with two hops → `valid=True`, `hop_count=2`
- Tampered token (modified `principal.id`) → `valid=False`
- Expired token → `valid=True` but `expired=True`

**`handle_tool_call`**
- Routes `hdp_issue_token` correctly
- Routes `hdp_extend_chain` with snake_case args
- Routes `hdp_extend_chain` with camelCase args (`delegateeId`, `additionalScope`)
- Routes `hdp_verify_token` correctly
- Unknown name → raises `ValueError` with message listing supported names

**`reset()`**
- Clears `_current_token` to `None` and `_hop_count` to 0
- `session_id` and `principal_id` preserved after reset

**Inspection**
- `export_current_token()` returns `None` before `issue_token`
- `export_current_token()` returns token dict after `issue_token`
- `__repr__` contains `session_id`, hop count, and valid flag
