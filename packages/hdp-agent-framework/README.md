# hdp-agent-framework

**HDP (Human Delegation Provenance) middleware for Microsoft agent-framework** — attach a
cryptographic audit trail to any agent or multi-agent workflow with zero changes to
your existing code.

Every chat call and tool invocation is recorded in a tamper-evident chain of Ed25519
signatures, verifiable fully **offline** with a single public key.

```
pip install hdp-agent-framework
```

---

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient
from azure.identity.aio import AzureCliCredential
from hdp_agent_framework import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain

private_key = Ed25519PrivateKey.generate()

middleware = HdpMiddleware(
    signing_key=private_key.private_bytes_raw(),
    session_id="analysis-2026",
    principal=HdpPrincipal(id="analyst@corp.com", id_type="email"),
    scope=ScopePolicy(
        intent="Analyse Q1 sales data and generate a summary",
        authorized_tools=["fetch_data", "write_report"],
        max_hops=5,
    ),
)

agent = Agent(
    client=FoundryChatClient(credential=AzureCliCredential()),
    name="sales_analyst",
    tools=[...],
)

# Attach HDP — one line, zero agent changes
middleware.configure(agent)
await agent.run("Analyse Q1 EMEA sales and write a summary.")

# Verify the delegation chain offline — no network call
result = verify_chain(middleware.export_token(), private_key.public_key())
print(result.valid)       # True
print(result.hop_count)   # number of agent turns recorded
```

---

## Five design considerations

| # | Consideration | How it's handled |
|---|---|---|
| **1** | **Scope observation** | Tool calls are compared with declared `authorized_tools`; out-of-scope attempts are recorded without gating the call. |
| **2** | **Recording depth** | `ScopePolicy(max_hops=N)` caps the recorded chain. Agent-framework actions continue after the chain is full. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each. Recording failures are logged as warnings. |
| **4** | **Verification** | `verify_chain(token, public_key)` checks record integrity offline. `valid` covers integrity only; `recorded_after_period` lists hop sequence numbers at or after `expires_at`. |
| **5** | **Agent integration** | `configure()` appends `HdpMiddleware` (chat middleware) and `_function_middleware` (tool middleware) to `agent.middleware`. Works with a single Agent or a list. |

---

## API reference

### `HdpMiddleware`

```python
HdpMiddleware(
    signing_key: bytes,           # Ed25519 private key (raw 32 bytes)
    session_id: str,              # unique ID for this session
    principal: HdpPrincipal,      # the human delegating authority
    scope: ScopePolicy,           # what is authorised
    key_id: str = "default",      # label stored in the token header
    expires_in_ms: int = 86400000,
    strict: bool = False,         # Deprecated; True raises ValueError at construction
)
```

| Method | Description |
|---|---|
| `configure(target)` | Attach to an `Agent` or list of Agents |
| `export_token()` | Return the token dict (or `None` before first call) |
| `export_token_json()` | Return the token as a JSON string |

### `verify_chain(token, public_key)`

```python
result = verify_chain(token_dict, public_key)   # Ed25519PublicKey or raw bytes
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

## Record-only behavior

Out-of-scope tool calls are recorded in the signed chain and `call_next()` runs for every call. `strict=True` is retained for compatibility and raises `ValueError` during construction. The deprecated `HDPScopeViolationError` remains importable but is never raised.

After a session, inspect recorded violations:

```python
token = middleware.export_token()
for v in token["scope"].get("extensions", {}).get("scope_violations", []):
    print(f"Violation: {v['tool']} at {v['timestamp']}")
```

---

## Session and key management

### Session ID uniqueness

Use a unique `session_id` per delegation session, for example a UUID generated at
session start. Each token embeds the session ID in the root signature. If two sessions
share the same ID:

- Cryptographic security is unaffected (each token has its own independent chain)
- Audit correlation becomes ambiguous in logs indexed by session ID.

```python
import uuid
middleware = HdpMiddleware(
    signing_key=key,
    session_id=str(uuid.uuid4()),  # unique per session
    ...
)
```

### Key rotation

Ed25519 key pairs are long-lived credentials. Rotate them periodically by generating a
new key pair and updating `signing_key` and `key_id` for new sessions.

```python
new_key = Ed25519PrivateKey.generate()

middleware = HdpMiddleware(
    signing_key=new_key.private_bytes_raw(),
    key_id="2026-Q3",             # label stored in token header
    session_id=str(uuid.uuid4()),
    ...
)
```

Tokens issued before rotation remain verifiable with the old public key.
There is no built-in revocation — the protocol is intentionally offline-first.
Revocation must be handled at the application layer (e.g., by publishing a revocation
list keyed on `key_id`).

---

## Cross-language compatibility

HDP tokens use the same wire format across all language SDKs (RFC 8785 canonical JSON
+ Ed25519). A token issued by `hdp-agent-framework` (Python) can be verified by
`@helixar_ai/hdp` (TypeScript) and vice versa.

```python
# Python: export token
token_json = middleware.export_token_json()
# → pass to TypeScript service via API, message queue, etc.
```

```typescript
// TypeScript: verify a token issued by Python
import { verifyChain } from "@helixar_ai/hdp";
const result = verifyChain(JSON.parse(tokenJson), publicKey);
```

---

## Releasing

Published to [PyPI](https://pypi.org/project/hdp-agent-framework/) via GitHub Actions:

```bash
git tag python/hdp-agent-framework/v0.1.0 && git push origin python/hdp-agent-framework/v0.1.0
```

Pipeline: `test-hdp-agent-framework` → `vet-hdp-agent-framework` ([ReleaseGuard](https://github.com/Helixar-AI/ReleaseGuard)) → `publish-hdp-agent-framework`

| Detail | Value |
|---|---|
| **PyPI project** | [`hdp-agent-framework`](https://pypi.org/project/hdp-agent-framework/) |
| **Tag pattern** | `python/hdp-agent-framework/v*` |
| **Workflow** | `.github/workflows/release.yml` |
| **Auth** | OIDC trusted publisher (no token needed) |
| **Environment** | `pypi-hdp-agent-framework` |

---

## Spec & citation

HDP is an IETF draft standard:
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/) ([draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03))

Protocol specification and documentation:
[helixar.ai/about/labs/hdp/](https://helixar.ai/about/labs/hdp/)

If you use HDP in research, please cite:

```bibtex
@misc{dalugoda2026hdp,
  title        = {{HDP}: A Lightweight Cryptographic Protocol for Human Delegation
                  Provenance in Agentic {AI} Systems},
  author       = {Dalugoda, Asiri},
  year         = {2026},
  month        = apr,
  eprint       = {2604.04522},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR},
  url          = {https://arxiv.org/abs/2604.04522},
}
```

---

## References

- [HDP protocol spec and docs](https://helixar.ai/about/labs/hdp/)
- [arXiv paper (2604.04522)](https://arxiv.org/abs/2604.04522)
- [HDP GitHub repository](https://github.com/Helixar-AI/HDP)
- [IETF draft: draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)
- [hdp-agent-framework on PyPI](https://pypi.org/project/hdp-agent-framework/)

---

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) — Helixar Limited
