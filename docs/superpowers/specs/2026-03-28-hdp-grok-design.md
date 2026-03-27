# hdp-grok Design Spec

**Date:** 2026-03-28
**Status:** Approved
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
│   │                      # exposes: issue_root_token(), extend_token_chain(), verify_token()
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

Standalone copy of the Ed25519 + RFC 8785 signing scheme used in `hdp-crewai`. Same wire format — tokens produced by `hdp-grok` are verifiable by the TypeScript SDK and vice versa.

Three high-level functions exposed for use by `HdpMiddleware`:

### `issue_root_token(signing_key, key_id, session_id, principal_id, scope, expires_in) -> dict`

Builds and signs the root HDP token dict:
- `header`: `token_id` (UUID), `issued_at`, `expires_at`, `session_id`, `version="0.1"`
- `principal`: `id=principal_id`, `id_type="opaque"`
- `scope`: `intent` (from `principal_id`), `authorized_tools=scope`
- `chain`: `[]`
- `signature`: Ed25519 over RFC 8785 canonical `{header, principal, scope}`

### `extend_token_chain(parent_token, signing_key, key_id, delegatee_id, additional_scope) -> dict`

Appends a signed hop to the existing chain:
- hop fields: `seq`, `agent_id=delegatee_id`, `agent_type="sub-agent"`, `timestamp`, `action_summary`, `parent_hop`
- `hop_signature`: Ed25519 over RFC 8785 canonical `{chain: cumulative, root_sig: root_sig_value}`
- Returns updated token dict

### `verify_token(token_str) -> dict`

Parses the token JSON, derives the Ed25519 public key from the stored `alg` metadata, and verifies:
- Root signature over `{header, principal, scope}`
- Each hop signature over its cumulative chain

Returns a result dict matching `HdpMiddleware.verify_token()` output shape.

> **Note:** Since `hdp-grok` is fully standalone (no shared key registry), `verify_token` verifies structural integrity and signature consistency. Callers who need cross-party verification must pass the signer's public key explicitly — a `verify_token_with_key(token_str, public_key_bytes)` overload will be added.

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
1. If `None` → read `HDP_SIGNING_KEY` env var → raise `HdpSigningKeyError` if absent
2. If `str` starting with `"0x"` → `bytes.fromhex(s[2:])`
3. If `str` → try base64url decode → fallback to hex decode

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
    # Raises HdpTokenMissingError, HdpTokenExpiredError

def verify_token(self, token: str) -> dict:
    """Returns:
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
    Raises ValueError for unrecognised tool names."""
```

### Inspection

```python
def export_current_token(self) -> dict | None:
    """Live in-memory token dict, or None before issue_token."""

def __repr__(self) -> str:
    # "HdpMiddleware(session_id='abc-123', hops=2, valid=True)"
```

---

## Tools (`tools.py`)

Three tool schemas in OpenAI-compatible format, updated to match the stateful middleware (no `session_id`/`principal_id` in `hdp_issue_token` — those live on the middleware instance):

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

### Tag
`python/hdp-grok/v*` (e.g. `python/hdp-grok/v0.1.0`)

Independent from `python/v*` (hdp-crewai) and `v*` (npm packages).

### New jobs in `release.yml`

```
test-hdp-grok
  if: startsWith(github.ref, 'refs/tags/python/hdp-grok/v')
  matrix: Python 3.10 / 3.11 / 3.12 (runs pytest)
    ↓
vet-hdp-grok
  needs: test-hdp-grok
  - python -m build
  - ReleaseGuard (pinned SHA: 94c067008f3ad516d4b61a6e7163d9d5518a4548)
  - upload artifact: hdp-grok-dist
    ↓
publish-hdp-grok
  needs: vet-hdp-grok
  - download hdp-grok-dist
  - pypa/gh-action-pypi-publish (OIDC, environment: pypi-hdp-grok)
```

### `packages/hdp-grok/.releaseguard.yml`

Mirrors `packages/hdp-crewai/.releaseguard.yml`:
- `add_checksums: false` (PyPI rejects non-dist files)
- `add_manifest: false`
- `secrets.enabled: true`
- `fail_on: [critical, secret]`

### CI (`ci.yml`)

New `test-hdp-grok` matrix job runs on every push/PR (Python 3.10 / 3.11 / 3.12).

---

## `pyproject.toml`

```toml
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
```

---

## Testing

`tests/test_middleware.py` covers:

- Key normalisation: bytes, base64url str, hex str, `0x`-prefixed hex, env var fallback
- `HdpSigningKeyError` when no key available
- `issue_token` happy path — token parses, signature verifiable
- `issue_token` raises `ValueError` when `principal_id` not set
- `extend_chain` happy path — hop appended, hop count incremented
- `extend_chain` raises `HdpTokenMissingError` before `issue_token`
- `extend_chain` raises `HdpTokenExpiredError` on expired token
- `verify_token` returns `valid=True` for a freshly issued token
- `verify_token` returns `valid=False` for tampered token
- `handle_tool_call` routes all three tool names correctly
- `handle_tool_call` raises `ValueError` for unknown tool name
- `reset()` clears token and hop count, preserves session/principal
- `export_current_token()` returns `None` before issue, dict after
- `__repr__` includes session_id, hops, valid
