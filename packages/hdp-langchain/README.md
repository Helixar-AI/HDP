# hdp-langchain

**HDP (Human Delegation Provenance) middleware for LangChain** — attach a cryptographic audit trail to any chain, agent, or tool with a single callback handler.

Every tool call in a LangChain agent is recorded in a tamper-evident chain of Ed25519 signatures, verifiable offline with a single public key.

```
pip install hdp-langchain
```

---

## Quick start — LangChain

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_react_agent
from hdp_langchain import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain

# 1. Your signing key (store in a secrets manager, never in code)
private_key = Ed25519PrivateKey.generate()

# 2. Define what the human is authorising
scope = ScopePolicy(
    intent="Research agent to summarise recent papers",
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

# 4. Build your agent as normal
agent_executor = AgentExecutor(agent=..., tools=[...])

# 5. Attach HDP — one line, zero agent changes
handler = middleware.get_callback_handler()
agent_executor.invoke(
    {"input": "Summarise recent LLM papers"},
    config={"callbacks": [handler]},
)

# 6. Verify the delegation chain offline
result = verify_chain(middleware.export_token(), private_key.public_key())
print(result.valid, result.hop_count, result.violations)
```

---

## Quick start — LangGraph

```python
from langgraph.graph import StateGraph, END
from hdp_langchain import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain
from hdp_langchain.graph import hdp_node

middleware = HdpMiddleware(
    signing_key=private_key.private_bytes_raw(),
    session_id="graph-session-1",
    principal=HdpPrincipal(id="user@example.com", id_type="email"),
    scope=ScopePolicy(intent="Multi-node research pipeline"),
)

# Wrap node functions — each execution records a delegation hop
@hdp_node(middleware, agent_id="planner")
def planner_node(state):
    return {**state, "plan": "step 1, step 2"}

@hdp_node(middleware, agent_id="executor")
def executor_node(state):
    return {**state, "result": "done"}

# Build and run the graph
graph = StateGraph(dict)
graph.add_node("planner", planner_node)
graph.add_node("executor", executor_node)
graph.add_edge("planner", "executor")
graph.add_edge("executor", END)
graph.set_entry_point("planner")

app = graph.compile()
app.invoke({})

# Verify the full delegation chain
result = verify_chain(middleware.export_token(), private_key.public_key())
print(result.valid, result.hop_count)  # True, 2
```

---

## Five design considerations

| # | Consideration | How it's handled |
|---|---|---|
| **1** | **Scope enforcement** | Tool calls are checked against `authorized_tools` in `on_tool_start`. Default: logs + records violation in token. `strict=True`: raises `HDPScopeViolationError`. |
| **2** | **Delegation depth** | `ScopePolicy(max_hops=N)` enforced per run; hops beyond the limit are skipped and logged. |
| **3** | **Token size / performance** | Ed25519 signatures are 64 bytes each (~2.6 KB for a 10-hop run). All HDP operations are non-blocking — failures log as warnings, execution always continues. |
| **4** | **Verification** | `verify_chain(token, public_key)` validates root + every hop signature offline. Returns `VerificationResult` with `valid`, `hop_count`, `violations`, and per-hop outcomes. |
| **5** | **Callback integration** | `get_callback_handler()` returns an `HdpCallbackHandler` compatible with LangChain's `RunnableConfig`. For LangGraph, use `hdp_node()` to wrap node functions. |

---

## API reference

### `HdpMiddleware`

```python
HdpMiddleware(
    signing_key: bytes,          # Ed25519 private key (raw 32 bytes)
    session_id: str,             # unique ID for this run
    principal: HdpPrincipal,     # the human delegating authority
    scope: ScopePolicy,          # what is authorised
    key_id: str = "default",     # label stored in the token header
    expires_in_ms: int = 86400000,
    strict: bool = False,        # True → raise on scope violations
)
```

| Method | Description |
|---|---|
| `get_callback_handler()` | Return an `HdpCallbackHandler` for use with LangChain's `RunnableConfig` |
| `export_token()` | Return the token dict (or `None` before first run) |
| `export_token_json()` | Return the token as a JSON string |

### `HdpCallbackHandler`

A `langchain_core.callbacks.BaseCallbackHandler` subclass. Attach via `RunnableConfig`:

```python
config = {"callbacks": [middleware.get_callback_handler()]}
chain.invoke(input, config=config)
```

### `hdp_node(middleware, node_fn=None, *, agent_id=None)`

Wraps a LangGraph node function to record a delegation hop on each invocation:

```python
@hdp_node(middleware, agent_id="researcher")
def researcher_node(state):
    ...
    return state
```

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

By default, HDP middleware is **non-blocking** — signing or scope-check failures are logged as warnings and execution continues normally. Violations are recorded in the token for post-hoc audit.

```python
# Default (non-blocking): violations are logged, execution keeps running
middleware = HdpMiddleware(
    signing_key=key, session_id="s1",
    principal=HdpPrincipal(id="alice", id_type="handle"),
    scope=ScopePolicy(intent="research", authorized_tools=["web_search"]),
)
handler = middleware.get_callback_handler()
# If the agent calls an unauthorised tool (e.g. "execute_code"):
# → WARNING is logged, violation attached to the token
# → execution is NOT interrupted

# Strict mode: violations raise immediately
middleware_strict = HdpMiddleware(
    ...,
    strict=True,
)
# If the agent calls "execute_code" → raises HDPScopeViolationError
```

---

## Cross-language compatibility

Python and TypeScript HDP tokens use the same wire format (RFC 8785 canonical JSON + Ed25519). A token issued by `hdp-langchain` (Python) can be verified by `@helixar_ai/hdp` (TypeScript) and vice versa.

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

## Spec

Human Delegation Provenance (HDP) is an IETF draft:
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — Helixar Limited
