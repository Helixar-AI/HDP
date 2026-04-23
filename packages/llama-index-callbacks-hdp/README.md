# llama-index-callbacks-hdp

HDP (Human Delegation Provenance) integration for LlamaIndex — cryptographic authorization provenance for agents and RAG pipelines.

HDP answers the question that observability tools like Arize Phoenix and Langfuse cannot: **who authorized this agent run, under what scope, and can you prove it offline?**

Every tool call, retrieval step, and LLM invocation is recorded in a tamper-evident, cryptographically signed delegation chain. The chain is fully verifiable offline — no network calls, no central registry.

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

### Option 3 — Node postprocessor (inline retrieval enforcement)

```python
from llama_index.callbacks.hdp import HdpNodePostprocessor

postprocessor = HdpNodePostprocessor(
    signing_key=ed25519_private_key_bytes,
    strict=False,
    check_data_classification=True,
)
query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
```

### Verifying a token

```python
from llama_index.callbacks.hdp import verify_chain

result = verify_chain(token_dict, public_key_bytes)
if result.valid:
    print(f"Chain verified: {result.hop_count} hops")
```

## What makes HDP different from Arize/Langfuse?

| Capability | Arize / Langfuse | HDP |
|---|---|---|
| Records what happened | ✓ | ✓ |
| Records who authorized it | ✗ | ✓ |
| Cryptographically signed | ✗ | ✓ |
| Verifiable offline | ✗ | ✓ |
| Scope enforcement | ✗ | ✓ |
| No central registry | n/a | ✓ |

## License

Apache-2.0
