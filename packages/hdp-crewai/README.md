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
| **1** | **Scope enforcement** | `step_callback` checks every `AgentAction.tool` against `authorized_tools`. Default: logs + records violation in token. `strict=True`: raises `HDPScopeViolationError`. |
| **2** | **Delegation depth** | `ScopePolicy(max_hops=N)` enforced per crew run; hops beyond the limit are skipped and logged. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each (~2.6 KB for a 10-hop crew). All HDP operations are non-blocking — failures log as warnings, the crew always continues. |
| **4** | **Verification** | `verify_chain(token, public_key)` validates root + every hop signature offline. Returns `VerificationResult` with `valid`, `hop_count`, `violations`, and per-hop outcomes. |
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
    strict: bool = False,        # True → raise on scope violations
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
```

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
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) — Helixar Limited
