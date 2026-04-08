# LlamaIndex Integration — Design Spec
**Date:** 2026-04-08  
**Status:** Approved for implementation planning

---

## Problem Statement

HDP provides cryptographic chain-of-custody for agentic AI systems. It currently integrates with MCP, CrewAI, AutoGen (Python + TypeScript), Grok/xAI, and LangChain. LlamaIndex is a major gap — it is widely used for RAG pipelines, multi-step agents, and workflow orchestration, but has no HDP integration today.

The goal is to add full native support for LlamaIndex and run a sequenced campaign to drive visibility and endorsement from the LlamaIndex maintainers and community.

---

## Constraints

- LlamaIndex's main repo (`run-llama/llama_index`) **no longer accepts new integration packages** — PRs adding a `pyproject.toml` are auto-closed. The contribution path is: publish independently to PyPI, submit to LlamaHub for discovery.
- LlamaIndex docs PRs (guides, examples for external packages) are still accepted.
- The integration must follow the LlamaIndex implicit namespace package convention for LlamaHub listing.
- No external network calls in the hot path — consistent with HDP's offline-verification design.

---

## Approach: Full Integration, One Shot

Build all three integration surfaces simultaneously and dual-publish. Run the LlamaHub + docs + blog campaign after the package is live.

---

## Technical Architecture

### Package Structure

Two published packages:

**`llama-index-callbacks-hdp`** (primary, PyPI + LlamaHub namespace)
- Uses the `llama_index.*` implicit namespace so users import from the standard LlamaIndex path
- Registered in LlamaHub via `[tool.llamahub]` metadata
- Category: `callbacks` (for LlamaHub discoverability)

**`hdp-llamaindex`** (metapackage, PyPI)
- Thin wrapper that depends on `llama-index-callbacks-hdp`
- Allows `pip install hdp-llamaindex` for users who discover HDP first

### Module Layout

```
llama-index-callbacks-hdp/
├── llama_index/callbacks/hdp/
│   ├── __init__.py         ← public exports
│   ├── session.py          ← shared ContextVar token state
│   ├── instrumentation.py  ← Layer 1: modern dispatcher integration
│   ├── callbacks.py        ← Layer 2: legacy CallbackManager integration
│   └── postprocessor.py    ← Layer 3: node postprocessor
├── tests/
└── pyproject.toml
```

### Shared Session State (`session.py`)

A `ContextVar[HdpToken | None]` holds the active token for the duration of a query. This is the glue between the three layers — it works correctly across `asyncio` tasks because Python's `ContextVar` is task-local by default.

Helper functions in this module:
- `get_token() → HdpToken | None`
- `set_token(token: HdpToken) → None`
- `clear_token() → None`

### Token Lifecycle Mapped to LlamaIndex Events

| LlamaIndex Signal | Layer | HDP Operation |
|-------------------|-------|---------------|
| `QueryStartEvent` / `start_trace` | 1 + 2 | `issueToken()` → store in ContextVar |
| `AgentToolCallEvent` / `FUNCTION_CALL` | 1 + 2 | `extendChain()` with tool name as action summary |
| `LLMChatStartEvent` / `LLM` start | 1 + 2 | Annotate current hop metadata |
| `ExceptionEvent` / `EXCEPTION` | 1 + 2 | Record anomaly in chain (does not invalidate token) |
| `QueryEndEvent` / `end_trace` | 1 + 2 | Finalize token, call optional `on_token_ready` callback |
| `_postprocess_nodes()` | 3 | Read token from ContextVar, validate scope, extend chain with retrieval hop |

---

## Layer 1 — Modern Instrumentation Handler

**Class:** `HdpInstrumentationHandler` implementing `BaseInstrumentationHandler`

**Entry point:** A classmethod `init()` that wires handlers to the root `llama_index.core.instrumentation` dispatcher.

**Parameters:**
- `signing_key` — Ed25519 private key bytes
- `principal` — `HdpPrincipal` identifying the authorizing human
- `scope` — `ScopePolicy` (intent string, authorized tools list, max hops, data classification)
- `key_id` — key identifier for rotation support
- `on_violation` — `"log"` (default) or `"raise"`
- `on_token_ready` — optional callable invoked with the final token at query end

**Internal components wired at `init()` time:**

`HdpEventHandler(BaseEventHandler)`  
Single abstract method: `handle(event: BaseEvent)`. Dispatches on event type to issue token, extend chain, annotate hops, or finalize.

`HdpSpanHandler(BaseSpanHandler)`  
Tags each new span with the active token ID for cross-tool trace correlation. Logs span drops with token context. Does not manage token lifecycle (that belongs to the event handler).

**Why both?** The event handler manages the delegation chain. The span handler enables token-to-span correlation for users running HDP alongside Arize Phoenix or Langfuse — their traces can be joined to the HDP audit record by token ID.

---

## Layer 2 — Legacy Callback Handler

**Class:** `HdpCallbackHandler` implementing `BaseCallbackHandler`

For users on older LlamaIndex versions or who configure via `Settings.callback_manager`.

**Parameters:**
- Same as Layer 1 (`signing_key`, `principal`, `scope`, `key_id`, `strict`)
- `strict=False` default (observe mode: log violations, continue); `strict=True` raises `HDPScopeViolationError`

**The four required abstract methods:**

`start_trace(trace_id)`  
Issues root token using `trace_id` as the session ID. Stores in ContextVar.

`end_trace(trace_id, trace_map)`  
Emits/finalizes the token. If `on_token_ready` is set, calls it here.

`on_event_start(event_type, payload, event_id, parent_id)`  
Routes on `CBEventType`:
- `QUERY` → records query intent in current hop metadata
- `FUNCTION_CALL` → calls `extendChain()` with tool name from `EventPayload.TOOL`
- `LLM` → annotates hop with model name from `EventPayload.MODEL_NAME`
- `EXCEPTION` → records anomaly

`on_event_end(event_type, payload, event_id)`  
Routes on `CBEventType`:
- `FUNCTION_CALL` → records output summary from `EventPayload.FUNCTION_OUTPUT`
- All others → noop

**Design note:** `start_trace` is the correct hook for issuing the root token, not `on_event_start(QUERY)`, because `start_trace` is always called first and provides the trace ID for session binding. This matches the pattern used by Langfuse and Arize in LlamaIndex.

---

## Layer 3 — Node Postprocessor

**Class:** `HdpNodePostprocessor` implementing `BaseNodePostprocessor`

Runs after retrieval, before synthesis. Validates scope and records retrieval as a hop.

**Parameters:**
- `strict=False` — observe mode (log violations, return all nodes); `strict=True` raises `HDPScopeViolationError`
- `check_data_classification=True` — if enabled, inspects node metadata for a `classification` field and validates against `scope.data_classification`

**`_postprocess_nodes(nodes, query_bundle)` logic:**

1. Read active token from ContextVar. If none: emit warning, return nodes unchanged.
2. Extract query string from `query_bundle`. Log it against `scope.intent` for audit purposes.
3. If `check_data_classification` is enabled: inspect each node's metadata for a `classification` key. If any node's classification exceeds the allowed level in scope: log violation or raise (depending on `strict`).
4. Call `extendChain()` with `action_summary = f"retrieval: {len(nodes)} nodes"` to record retrieval in the delegation chain.
5. Return nodes (all in observe mode; filtered or none in strict mode on violation).

**What this enables:** A RAG pipeline where every retrieval step is recorded in the delegation chain. The final HDP token proves which human authorized which query, which tools were used, and which documents were retrieved — all cryptographically.

---

## Dual-Publish Strategy

**`llama-index-callbacks-hdp`**
- Primary package
- Follows LlamaIndex implicit namespace convention (PEP 420)
- `[tool.llamahub]` section in `pyproject.toml` for LlamaHub registration
- LlamaHub submission: PR to `run-llama/llama_hub` repo

**`hdp-llamaindex`**
- Metapackage: `install_requires = ["llama-index-callbacks-hdp"]`
- Re-exports for convenience from `hdp_llamaindex` namespace (for users who discover HDP first)
- Maintained in the existing HDP packages directory

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `llama-index-core` | `>=0.10.20,<0.15` | Core abstractions (BaseEventHandler, BaseCallbackHandler, BaseNodePostprocessor, instrumentation dispatcher) |
| `llama-index-instrumentation` | `>=0.1.0` | Standalone instrumentation package (BaseEventHandler, BaseSpanHandler) |
| `cryptography` | `>=42.0.0` | Ed25519 signing (bundled inline, consistent with all other HDP Python packages) |
| `jcs` | `>=0.2.1` | RFC 8785 canonical JSON (bundled inline) |

**Note on HDP core:** All HDP Python packages (`hdp-crewai`, `hdp-autogen`, `hdp-grok`) bundle `_crypto.py` and `_types.py` inline rather than depending on a separate `hdp` PyPI package. The llamaindex package follows the same pattern.

---

## Error Handling

- **No active token:** All three layers gracefully degrade — they log a warning and do not raise. This ensures HDP does not break applications that haven't configured it at startup.
- **Scope violation (observe mode):** Log at WARNING level with full context (tool name, scope, token ID). Never raise.
- **Scope violation (strict mode):** Raise `HDPScopeViolationError` with the same context. Applications may catch this to implement custom fallback.
- **Chain extension failure:** Log at ERROR level, do not swallow. The underlying HDP SDK error propagates.

---

## Testing

Each layer has its own test module:
- `tests/test_instrumentation.py` — fires synthetic LlamaIndex events, verifies token is issued and extended correctly
- `tests/test_callbacks.py` — exercises all four abstract methods in sequence
- `tests/test_postprocessor.py` — verifies node pass-through, violation logging, and chain extension
- `tests/test_session.py` — verifies ContextVar isolation across concurrent async tasks
- `tests/test_integration.py` — end-to-end: a minimal LlamaIndex query pipeline exercising all three layers together

---

## Campaign Strategy

### Phase 1: Publish + LlamaHub Listing

Deliverables:
- Both packages live on PyPI
- LlamaHub listing PR merged (`run-llama/llama_hub`)
- README clearly stating the differentiation: HDP records *authorization provenance*, not just telemetry

Success metric: LlamaHub listing live, PyPI download count accumulating. Begin Phase 2 outreach once the package has at least 2 weeks of install history on PyPI — even a modest count signals real usage and gives the docs PR a concrete "this is already being used" data point.

### Phase 2: Docs PR to run-llama/llama_index

Target: `docs/docs/understanding/tracing/` or `docs/examples/observability/`

What the PR contains:
- A written guide (no code artifacts) explaining the three integration paths
- Comparison to pure observability tools: what HDP adds that Arize/Langfuse don't (cryptographic provenance, offline verification, scope enforcement)
- Link to the LlamaHub listing and PyPI package

Why this is accepted: LlamaIndex docs PRs for external integrations are open. Only new in-repo packages are rejected.

Pitch approach: Open the PR with a link to the LlamaHub listing and download stats as social proof. Tag a maintainer (check `CODEOWNERS` for the `docs/` path).

Success metric: PR merged.

### Phase 3: Blog Co-Author Pitch

Timing: After Phase 2 PR is merged.

Target: `llamaindex.ai/blog` — they publish guest and co-authored technical posts.

Pitch angle:  
*"We built the first cryptographic chain-of-custody integration for LlamaIndex agents. Here is why authorization provenance is a different problem from observability — and why it matters for enterprise agentic systems."*

This is a novel technical story with a concrete, already-live implementation. It is not a product announcement; it is a technical contribution.

Outreach: LlamaIndex DevRel via their Discord `#community-announcements` channel or X (@jerryjliu0). Frame it as a technical piece that would be valuable to their enterprise-focused readers.

Success metric: Blog post published with LlamaIndex as co-author or publisher.

---

## What LlamaIndex Is Missing (The Gap This Fills)

LlamaIndex's current observability ecosystem (Arize Phoenix, Langfuse, Wandb, AgentOps, UpTrain) answers: *what happened and when?*

HDP answers: *who authorized it, under what scope, and can you prove it offline?*

No existing LlamaIndex integration provides:
- A cryptographically signed record of which human principal authorized a given agent run
- A tamper-evident delegation chain showing every tool call back to its authorization root
- Offline-verifiable tokens (no network calls, no central registry)
- Scope enforcement at the retrieval layer (the postprocessor integration)

This is the differentiated claim that makes this story compelling to the LlamaIndex maintainers and their enterprise audience.
