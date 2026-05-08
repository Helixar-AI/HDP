# HDP × Microsoft agent-framework — Promotion Plan

**Date:** 2026-05-09  
**Author:** Siri Dalugoda  
**Status:** Approved

---

## Overview

Three coordinated deliverables that introduce HDP (Human Delegation Provenance) to the Microsoft agent-framework community:

1. **`hdp-agent-framework`** — a new Python package published to PyPI, following the same structure and public API as `hdp-autogen`
2. **Thin PR to `microsoft/agent-framework`** — a single sample file in the existing `security/` directory that demos the integration without exposing HDP internals
3. **Discussion thread in `microsoft/agent-framework`** — community post cross-referencing the AutoGen validation thread and inviting feedback

---

## Part 1 — `hdp-agent-framework` Python Package

### Location

`packages/hdp-agent-framework/` in the HDP monorepo, following the same layout as `packages/hdp-autogen/`.

### Licence

Apache License 2.0 (`license = { text = "Apache-2.0" }` in `pyproject.toml`). Every source file carries the SPDX header:

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Helixar Limited
```

### Python version

`requires-python = ">=3.10"` — matches `hdp-autogen` and agent-framework-core.

### Dependencies

```toml
dependencies = [
    "agent-framework-core>=1.0",
    "cryptography>=42.0.0",
    "jcs>=0.2.1",
]
```

### Directory structure

```
packages/hdp-agent-framework/
├── pyproject.toml
├── README.md
└── src/
    └── hdp_agent_framework/
        ├── __init__.py
        ├── _crypto.py      # copied verbatim from hdp-autogen
        ├── _types.py       # copied verbatim from hdp-autogen
        ├── middleware.py   # NEW — ChatMiddleware + FunctionMiddleware integration
        └── verify.py       # copied verbatim from hdp-autogen
└── tests/
    ├── test_middleware.py
    └── test_verify.py
```

`_crypto.py`, `_types.py`, and `verify.py` are copied verbatim from `hdp-autogen` — no logic divergence, no new IP surface.

### Integration surface

agent-framework exposes two middleware abstractions:

| Class | Hook point | Used for |
|---|---|---|
| `ChatMiddleware` | Every chat client call (`ChatContext`) | Record each agent turn as a delegation hop |
| `FunctionMiddleware` | Every tool invocation (`FunctionInvocationContext`) | Enforce `authorized_tools`; record violations |

Both hook points are attached to an `Agent` via `Agent(middleware=[...])`.

### `middleware.py` design

**`HdpMiddleware(ChatMiddleware)`**

```python
class HdpMiddleware(ChatMiddleware):
    def __init__(
        self,
        signing_key: bytes,
        session_id: str,
        principal: HdpPrincipal,
        scope: ScopePolicy,
        key_id: str = "default",
        expires_in_ms: int = 86_400_000,
        strict: bool = False,
    ) -> None: ...

    async def process(self, context: ChatContext, call_next) -> None:
        # Before call_next: extend_chain(agent_id from context metadata or class name)
        # await call_next()
        # After: no-op (violations already recorded by HdpFunctionMiddleware)
        ...

    def configure(self, agent: Agent) -> None:
        # Injects self (ChatMiddleware) + HdpFunctionMiddleware into agent.middleware
        ...

    def export_token(self) -> dict | None: ...
    def export_token_json(self) -> str | None: ...
```

**`HdpFunctionMiddleware`** (internal, injected by `configure()`)

```python
class HdpFunctionMiddleware:
    async def __call__(
        self, context: FunctionInvocationContext, call_next
    ) -> None:
        # Check context.function.name against scope.authorized_tools
        # In strict mode: raise HDPScopeViolationError
        # Default mode: log + attach violation to current hop
        await call_next()
```

**`ScopePolicy`** — identical to `hdp-autogen`:

```python
ScopePolicy(
    intent: str,
    data_classification: str = "internal",
    network_egress: bool = True,
    persistence: bool = False,
    authorized_tools: list[str] | None = None,
    authorized_resources: list[str] | None = None,
    max_hops: int | None = None,
)
```

### Public API (`__init__.py`)

```python
from hdp_agent_framework import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain
```

Identical shape to `hdp-autogen` — users migrating between frameworks face zero API difference.

### README

Full README matching `hdp-autogen` style:

- One-liner and `pip install hdp-agent-framework`
- Quick-start code block (configure + run + verify)
- Five design considerations table (same headings as `hdp-autogen`)
- Full API reference (`HdpMiddleware`, `ScopePolicy`, `verify_chain`)
- Error handling section (strict vs. non-blocking)
- Cross-language compatibility note (Python ↔ TypeScript token wire format)
- Releasing section (tag pattern `python/hdp-agent-framework/v*`)
- References:
  - [HDP protocol spec and docs](https://helixar.ai/about/labs/hdp/)
  - [arXiv paper (2604.04522)](https://arxiv.org/abs/2604.04522)
  - [HDP GitHub repository](https://github.com/Helixar-AI/HDP)
  - [IETF draft: draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)
  - [hdp-agent-framework on PyPI](https://pypi.org/project/hdp-agent-framework/)

### CI / release

Tag pattern: `python/hdp-agent-framework/v*`  
Pipeline: `test-hdp-agent-framework` → `vet-hdp-agent-framework` (ReleaseGuard) → `publish-hdp-agent-framework`

---

## Part 2 — Thin PR to `microsoft/agent-framework`

### Target file

`python/samples/02-agents/security/hdp_provenance.py`

No changes to existing files. No new directory.

### Contents (~40 lines)

- Apache 2.0 + Microsoft copyright header (as per repo convention)
- `pip install hdp-agent-framework` comment at top
- Single `Agent` with `HdpMiddleware` attached via `middleware.configure(agent)`
- One `agent.run(task)` call
- Offline `verify_chain()` + print result
- Links to `helixar.ai/about/labs/hdp/` and PyPI in comments

**No crypto. No token format. No HDP internals.** The entire HDP implementation lives behind the PyPI package import.

### PR description

- Summary: what HDP is (one paragraph), why it matters for agent-framework
- Link to the PR we already raised against `microsoft/autogen` (#7667) as prior art
- Link to autogen community discussion #7485 for validation evidence
- Link to `helixar.ai/about/labs/hdp/` and the arXiv paper
- Test plan (install, run, verify chain prints `Valid: True`)

---

## Part 3 — Discussion Thread in `microsoft/agent-framework`

### Target

`https://github.com/microsoft/agent-framework/discussions` — new discussion.

### Framing

*"HDP delegation provenance for agent-framework — same integration we built for AutoGen"*

Content:
- One-paragraph problem statement (agents can't prove downstream actions were human-authorised)
- Link to the AutoGen community thread (#7485) as prior validation by the community
- Link to `hdp-agent-framework` on PyPI and the sample PR
- Link to `helixar.ai/about/labs/hdp/` and arXiv:2604.04522
- Open question: *"What agent-framework patterns would benefit most from provenance tracking — single-agent tool use, hierarchical `as_tool()` delegation, or workflow orchestration?"*

---

## Build sequence

```
1. packages/hdp-agent-framework/pyproject.toml + src/ skeleton
2. _crypto.py, _types.py, verify.py  (copy from hdp-autogen)
3. middleware.py (HdpMiddleware + HdpFunctionMiddleware)
4. README.md
5. tests/
6. CI workflow entry in .github/workflows/release.yml
7. Publish to PyPI (tag python/hdp-agent-framework/v0.1.0)
8. Fork microsoft/agent-framework, add hdp_provenance.py, open PR
9. Post discussion thread in microsoft/agent-framework
```

---

## Acceptance criteria

| Deliverable | Done when |
|---|---|
| Package | `pip install hdp-agent-framework` works; `middleware.configure(agent)` attaches; `verify_chain()` returns `valid=True` on a real agent run |
| PR | Opens against `microsoft/agent-framework` main; CI passes; no HDP internals inlined |
| Discussion | Posted with all links; references autogen discussion and arXiv paper |
