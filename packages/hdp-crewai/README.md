# hdp-crewai

**HDP (Human Delegation Provenance) middleware for CrewAI** — attach a cryptographic audit trail to any multi-agent crew with zero changes to your existing code.

Every task a CrewAI crew executes on behalf of a human is recorded in a tamper-evident chain of Ed25519 signatures, verifiable offline with a single public key.

```
pip install hdp-crewai
```

---

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crewai import Agent, Crew, Task
from hdp_crewai import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain

# 1. Your signing key (store in a secrets manager, never in code)
private_key = Ed25519PrivateKey.generate()

# 2. Define what the human is authorising
scope = ScopePolicy(
    intent="Analyse Q1 sales data and produce a summary",
    authorized_tools=["FileReadTool", "CSVAnalysisTool"],
    max_hops=5,
)

# 3. Create the middleware
middleware = HdpMiddleware(
    signing_key=private_key.private_bytes_raw(),
    session_id="q1-review-2026",
    principal=HdpPrincipal(id="analyst@company.com", id_type="email"),
    scope=scope,
)

# 4. Build your crew as normal
crew = Crew(agents=[...], tasks=[...])

# 5. Attach HDP — one line, zero crew changes
middleware.configure(crew)
crew.kickoff()

# 6. Verify the delegation chain offline
result = verify_chain(middleware.export_token(), private_key.public_key())
print(result.valid, result.hop_count, result.violations)
```

---

## Five design considerations

| # | Consideration | How it's handled |
|---|---|---|
| **1** | **Scope observation** | `step_callback` compares each `AgentAction.tool` with the declared `authorized_tools` and records out-of-scope attempts. It does not gate tools. |
| **2** | **Recording depth** | `ScopePolicy(max_hops=N)` caps the recorded chain. CrewAI actions continue after the chain is full. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each (~2.6 KB for a 10-hop crew). Recording failures are logged as warnings. |
| **4** | **Verification** | `verify_chain(token, public_key)` checks record integrity offline. `valid` covers integrity only; `recorded_after_period` lists hop sequence numbers at or after `expires_at`. |
| **5** | **Memory integration** | `after_kickoff` persists the signed token JSON to CrewAI's storage directory (`db_storage_path()`) alongside task outputs for retroactive auditing. |

---

## API reference

### `HdpMiddleware`

```python
HdpMiddleware(
    signing_key: bytes,          # Ed25519 private key (raw 32 bytes)
    session_id: str,             # unique ID for this crew run
    principal: HdpPrincipal,     # the human delegating authority
    scope: ScopePolicy,          # what is authorised
    key_id: str = "default",     # label stored in the token header
    expires_in_ms: int = 86400000,
    strict: bool = False,        # Deprecated; True raises ValueError at construction
    persist_token: bool = True,  # False → skip storage write
)
```

| Method | Description |
|---|---|
| `configure(crew)` | Attach all hooks to a `Crew` instance |
| `export_token()` | Return the token dict (or `None` before kickoff) |
| `export_token_json()` | Return the token as a JSON string |

### `verify_chain(token, public_key)`

```python
result = verify_chain(token_dict, public_key)  # Ed25519PublicKey or raw bytes
result.valid        # bool
result.hop_count    # int
result.violations   # list[str]
result.hop_results  # list[HopVerification]
result.recorded_after_period  # list[int] of hop seq values at or after expires_at
```

HDP tokens are records and cannot gate actions. `authorized_tools` records a declaration and does not authorize or block tool use. Expiry does not affect `valid`. The `strict` option remains for compatibility; setting it to `True` raises `ValueError` during construction. `HDPScopeViolationError` remains importable but is deprecated and never raised.

### `ScopePolicy`

```python
ScopePolicy(
    intent: str,
    data_classification: str = "internal",   # "public" | "internal" | "confidential" | "restricted"
    network_egress: bool = True,
    persistence: bool = False,
    authorized_tools: list[str] | None = None,
    authorized_resources: list[str] | None = None,
    max_hops: int | None = None,
)
```

---

## Spec

Human Delegation Provenance (HDP) is an IETF draft:
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/) ([draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03))

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) — Helixar Limited
