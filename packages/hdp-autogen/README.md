# hdp-autogen

**HDP (Human Delegation Provenance) middleware for AutoGen** — attach a cryptographic audit trail to any multi-agent conversation with zero changes to your existing code.

Every speaker turn in an AutoGen GroupChat is recorded in a tamper-evident chain of Ed25519 signatures, verifiable offline with a single public key.

```
pip install hdp-autogen
```

---

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autogen import ConversableAgent, GroupChat, GroupChatManager
from hdp_autogen import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain

# 1. Your signing key (store in a secrets manager, never in code)
private_key = Ed25519PrivateKey.generate()

# 2. Define what the human is authorising
scope = ScopePolicy(
    intent="Coordinate research agents to summarise recent papers",
    authorized_tools=["web_search", "file_reader"],
    max_hops=10,
)

# 3. Create the middleware
middleware = HdpMiddleware(
    signing_key=private_key.private_bytes_raw(),
    session_id="research-2026-q1",
    principal=HdpPrincipal(id="researcher@lab.edu", id_type="email"),
    scope=scope,
)

# 4. Build your agents as normal
researcher = ConversableAgent("researcher", ...)
reviewer = ConversableAgent("reviewer", ...)
groupchat = GroupChat(agents=[researcher, reviewer], messages=[])
manager = GroupChatManager(groupchat=groupchat, ...)

# 5. Attach HDP — one line, zero agent changes
middleware.configure(manager)
manager.run_chat(messages=[{"role": "user", "content": "Summarise recent LLM papers"}])

# 6. Verify the delegation chain offline
result = verify_chain(middleware.export_token(), private_key.public_key())
print(result.valid, result.hop_count, result.violations)
```

---

## Five design considerations

| # | Consideration | How it's handled |
|---|---|---|
| **1** | **Scope observation** | Incoming messages are inspected for tool calls against declared `authorized_tools`; out-of-scope attempts are recorded without gating the message. |
| **2** | **Recording depth** | `ScopePolicy(max_hops=N)` caps the recorded chain. AutoGen actions continue after the chain is full. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each (~2.6 KB for a 10-hop chat). Recording failures are logged as warnings. |
| **4** | **Verification** | `verify_chain(token, public_key)` checks record integrity offline. `valid` covers integrity only; `recorded_after_period` lists hop sequence numbers at or after `expires_at`. |
| **5** | **GroupChat integration** | `configure()` detects `ConversableAgent` vs `GroupChatManager` and attaches the appropriate hooks. Each speaker turn = one delegation hop. |

---

## API reference

### `HdpMiddleware`

```python
HdpMiddleware(
    signing_key: bytes,          # Ed25519 private key (raw 32 bytes)
    session_id: str,             # unique ID for this conversation
    principal: HdpPrincipal,     # the human delegating authority
    scope: ScopePolicy,          # what is authorised
    key_id: str = "default",     # label stored in the token header
    expires_in_ms: int = 86400000,
    strict: bool = False,        # Deprecated; True raises ValueError at construction
)
```

| Method | Description |
|---|---|
| `configure(target)` | Attach hooks to a `ConversableAgent`, `GroupChatManager`, or list of agents |
| `export_token()` | Return the token dict (or `None` before first message) |
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

## Record-only behavior

Out-of-scope tool calls are recorded in the signed chain and the message continues through AutoGen. `strict=True` is retained for compatibility and raises `ValueError` during construction. The deprecated `HDPScopeViolationError` remains importable but is never raised.

After a session, inspect recorded tool calls in the token:

```python
token = middleware.export_token()
for hop in token["delegation_chain"]:
    if hop.get("violation"):
        print(f"Hop {hop['seq']}: {hop['violation']}")
```

---

## Cross-language compatibility

Python and TypeScript HDP tokens use the same wire format (RFC 8785 canonical JSON + Ed25519). A token issued by `hdp-autogen` (Python) can be verified by `@helixar_ai/hdp` (TypeScript) and vice versa — useful in mixed environments where some agents run in Python and others in Node.js.

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

Published to [PyPI](https://pypi.org/project/hdp-autogen/) via GitHub Actions when a matching tag is pushed:

```bash
git tag python/hdp-autogen/v0.1.2 && git push origin python/hdp-autogen/v0.1.2
```

Pipeline: `test-hdp-autogen` → `vet-hdp-autogen` ([ReleaseGuard](https://github.com/Helixar-AI/ReleaseGuard)) → `publish-hdp-autogen`

| Detail | Value |
|---|---|
| **PyPI project** | [`hdp-autogen`](https://pypi.org/project/hdp-autogen/) |
| **Tag pattern** | `python/hdp-autogen/v*` |
| **Workflow** | `.github/workflows/release.yml` |
| **Auth** | OIDC trusted publisher (no token needed) |
| **Environment** | `pypi-hdp-autogen` |

---

## Spec

Human Delegation Provenance (HDP) is an IETF draft:
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) — Helixar Limited
