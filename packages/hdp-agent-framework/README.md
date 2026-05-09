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
| **1** | **Scope enforcement** | Tool calls are inspected against `authorized_tools`. Default: logs + records violation in token. `strict=True`: raises `HDPScopeViolationError`. |
| **2** | **Delegation depth** | `ScopePolicy(max_hops=N)` is enforced; hops beyond the limit are skipped and logged. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each. All HDP operations are non-blocking — failures log as warnings, the agent always continues. |
| **4** | **Verification** | `verify_chain(token, public_key)` validates root + every hop offline. Returns `VerificationResult` with `valid`, `hop_count`, `violations`, and per-hop outcomes. |
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
    strict: bool = False,         # True → raise on scope violations
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

## Error handling

By default, HDP middleware is **non-blocking** — violations are logged as warnings and
recorded in the token for post-hoc audit. The agent always continues.

```python
# Default (non-blocking): violations recorded, agent keeps running
middleware = HdpMiddleware(
    signing_key=key, session_id="s1",
    principal=HdpPrincipal(id="alice", id_type="handle"),
    scope=ScopePolicy(intent="research", authorized_tools=["web_search"]),
)
middleware.configure(agent)

# Strict mode: violations raise immediately
middleware_strict = HdpMiddleware(
    signing_key=key, session_id="s1",
    principal=HdpPrincipal(id="alice", id_type="handle"),
    scope=ScopePolicy(intent="research", authorized_tools=["web_search"]),
    strict=True,
)
```

After a session, inspect violations:

```python
token = middleware.export_token()
for v in token["scope"].get("extensions", {}).get("scope_violations", []):
    print(f"Violation: {v['tool']} at {v['timestamp']}")
```

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
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)

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
