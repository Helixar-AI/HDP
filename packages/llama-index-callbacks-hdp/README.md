# llama-index-callbacks-hdp

HDP (Human Delegation Provenance) integration for LlamaIndex, with cryptographic records of agent and RAG activity.

HDP complements observability tools like Arize Phoenix and Langfuse with an offline-verifiable record of the issuer-declared delegation context and subsequent signed chain entries.

Every tool call, retrieval step, and LLM invocation is recorded in a tamper-evident, cryptographically signed delegation chain. The chain is verifiable offline without network calls or a central registry. HDP tokens are records and cannot gate actions.

## Installation

```bash
pip install llama-index-callbacks-hdp
```

## Usage

### Option 1 — Modern instrumentation dispatcher (LlamaIndex ≥0.10.20)

```python
from llama_index.callbacks.hdp import HdpInstrumentationHandler, HdpPrincipal, ScopePolicy

HdpInstrumentationHandler.init(
    signing_key=ed25519_private_key_bytes,
    principal=HdpPrincipal(id="alice@corp.com", id_type="email"),
    scope=ScopePolicy(
        intent="Research pipeline",
        authorized_tools=["web_search", "retriever"],
        max_hops=10,
    ),
    on_token_ready=lambda token: print(token["header"]["token_id"]),
)
```

### Option 2 — Legacy CallbackManager

```python
from llama_index.callbacks.hdp import HdpCallbackHandler, HdpPrincipal, ScopePolicy
from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager

handler = HdpCallbackHandler(
    signing_key=ed25519_private_key_bytes,
    principal=HdpPrincipal(id="alice@corp.com", id_type="email"),
    scope=ScopePolicy(intent="Research pipeline"),
)
Settings.callback_manager = CallbackManager([handler])
```

### Option 3: Node postprocessor (retrieval audit recording)

```python
from llama_index.callbacks.hdp import HdpNodePostprocessor

postprocessor = HdpNodePostprocessor(
    signing_key=ed25519_private_key_bytes,
    check_data_classification=True,
)
query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
```

The postprocessor returns every node. Nodes above the declared `data_classification` are recorded as violations when a signing key is configured and the chain has capacity under `max_hops`. The deprecated `strict=True` and instrumentation's `on_violation="raise"` options raise `ValueError` during construction. `HDPScopeViolationError` remains importable but is deprecated and never raised.

### Verifying a token

```python
from llama_index.callbacks.hdp import verify_chain

result = verify_chain(token_dict, public_key_bytes)
if result.valid:
    print(f"Chain verified: {result.hop_count} hops")
print(result.recorded_after_period)  # hop seq values at or after expires_at
```

`result.valid` reports integrity only. Expiry does not affect it; `recorded_after_period` reports hops whose timestamps are at or after the authorization period.

## What makes HDP different from Arize/Langfuse?

| Capability | Arize / Langfuse | HDP |
|---|---|---|
| Records what happened | ✓ | ✓ |
| Records issuer-declared delegation context | ✗ | ✓ |
| Cryptographically signed | ✗ | ✓ |
| Verifiable offline | ✗ | ✓ |
| Scope declaration and violation records | ✗ | ✓ |
| No central registry | n/a | ✓ |

## Specification

This package follows [draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03) ([latest revision](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)).

## License

Apache-2.0
