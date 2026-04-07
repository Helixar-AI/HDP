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
| **1** | **Scope enforcement** | Incoming messages are inspected for tool calls against `authorized_tools`. Default: logs + records violation in token. `strict=True`: raises `HDPScopeViolationError`. |
| **2** | **Delegation depth** | `ScopePolicy(max_hops=N)` enforced per conversation; hops beyond the limit are skipped and logged. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each (~2.6 KB for a 10-hop chat). All HDP operations are non-blocking — failures log as warnings, agents always continue. |
| **4** | **Verification** | `verify_chain(token, public_key)` validates root + every hop signature offline. Returns `VerificationResult` with `valid`, `hop_count`, `violations`, and per-hop outcomes. |
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
    strict: bool = False,        # True → raise on scope violations
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

By default, HDP middleware is **non-blocking** — signing or scope-check failures are logged as warnings and the agent continues normally. Violations are recorded in the token's hop metadata for post-hoc audit.

```python
# Default (non-blocking): violations are logged, agents keep running
middleware = HdpMiddleware(
    signing_key=key, session_id="s1",
    principal=HdpPrincipal(id="alice", id_type="handle"),
    scope=ScopePolicy(intent="research", authorized_tools=["web_search"]),
)
middleware.configure(agent)
# If the agent calls an unauthorised tool (e.g. "execute_code"),
# → WARNING is logged, violation attached to the hop record
# → agent execution is NOT interrupted

# Strict mode: violations raise immediately
middleware_strict = HdpMiddleware(
    signing_key=key, session_id="s1",
    principal=HdpPrincipal(id="alice", id_type="handle"),
    scope=ScopePolicy(intent="research", authorized_tools=["web_search"]),
    strict=True,
)
middleware_strict.configure(agent)
# If the agent calls "execute_code" → raises HDPScopeViolationError
```

After a session, inspect violations via the token:

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

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — Helixar Limited
