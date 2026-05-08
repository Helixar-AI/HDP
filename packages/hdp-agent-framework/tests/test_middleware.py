# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""Failing tests for HdpMiddleware (agent-framework).

All tests in this file MUST FAIL until middleware.py is implemented (Task 4).
Expected failure reason: ImportError — HdpMiddleware, ScopePolicy,
HDPScopeViolationError are not yet exported from hdp_agent_framework.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hdp_agent_framework import (
    HdpMiddleware,
    HdpPrincipal,
    HDPScopeViolationError,
    ScopePolicy,
    verify_chain,
)


# ---------------------------------------------------------------------------
# Fakes — agent-framework duck-typed stand-ins (no real installation needed)
# ---------------------------------------------------------------------------

@dataclass
class FakeFunctionInfo:
    name: str


@dataclass
class FakeFunctionContext:
    function: FakeFunctionInfo


@dataclass
class FakeChatContext:
    metadata: dict = field(default_factory=dict)


class FakeAgent:
    def __init__(self, name: str = "agent-1"):
        self.name = name
        self.middleware: list = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_key() -> tuple[bytes, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub


def _make_middleware(
    scope: ScopePolicy | None = None,
    **kwargs,
) -> tuple[HdpMiddleware, bytes, Ed25519PublicKey]:
    key, pub = _generate_key()
    mw = HdpMiddleware(
        signing_key=key,
        session_id="test-session",
        principal=HdpPrincipal(id="user@test.com", id_type="email"),
        scope=scope or ScopePolicy(intent="Test intent"),
        **kwargs,
    )
    return mw, key, pub


async def _process(mw: HdpMiddleware, agent_name: str = "agent-1") -> None:
    """Run mw.process() with a fake context carrying the given agent_name."""
    ctx = FakeChatContext(metadata={"agent_name": agent_name})
    await mw.process(ctx, AsyncMock())


async def _function_middleware_call(mw: HdpMiddleware, tool_name: str) -> None:
    """Invoke mw._function_middleware with a fake function context."""
    ctx = FakeFunctionContext(function=FakeFunctionInfo(name=tool_name))
    await mw._function_middleware(ctx, AsyncMock())


# ---------------------------------------------------------------------------
# configure()
# ---------------------------------------------------------------------------

class TestConfigure:
    def test_configure_appends_middleware_to_agent(self):
        mw, _, _ = _make_middleware()
        agent = FakeAgent()
        mw.configure(agent)
        assert mw in agent.middleware

    def test_configure_appends_function_middleware_to_agent(self):
        mw, _, _ = _make_middleware()
        agent = FakeAgent()
        mw.configure(agent)
        assert mw._function_middleware in agent.middleware

    def test_configure_total_two_items_added(self):
        mw, _, _ = _make_middleware()
        agent = FakeAgent()
        mw.configure(agent)
        assert len(agent.middleware) == 2

    def test_configure_is_idempotent(self):
        """Calling configure() twice must not add duplicates."""
        mw, _, _ = _make_middleware()
        agent = FakeAgent()
        mw.configure(agent)
        mw.configure(agent)
        assert len(agent.middleware) == 2


# ---------------------------------------------------------------------------
# Lazy root issuance
# ---------------------------------------------------------------------------

class TestLazyRootIssuance:
    def test_export_token_none_before_process(self):
        mw, _, _ = _make_middleware()
        assert mw.export_token() is None

    @pytest.mark.asyncio
    async def test_export_token_valid_after_first_process(self):
        mw, _, _ = _make_middleware()
        await _process(mw)
        token = mw.export_token()
        assert token is not None
        assert token["hdp"] == "0.1"

    @pytest.mark.asyncio
    async def test_export_token_has_session_id_after_process(self):
        mw, _, _ = _make_middleware()
        await _process(mw)
        token = mw.export_token()
        assert token["header"]["session_id"] == "test-session"


# ---------------------------------------------------------------------------
# process() — chain extension
# ---------------------------------------------------------------------------

class TestProcessChainExtension:
    @pytest.mark.asyncio
    async def test_each_process_call_appends_one_hop(self):
        mw, _, _ = _make_middleware()
        await _process(mw, "agent-1")
        await _process(mw, "agent-2")
        assert len(mw.export_token()["chain"]) == 2

    @pytest.mark.asyncio
    async def test_agent_name_from_context_metadata_used_as_agent_id(self):
        mw, _, _ = _make_middleware()
        await _process(mw, "my-worker-agent")
        hop = mw.export_token()["chain"][0]
        assert hop["agent_id"] == "my-worker-agent"

    @pytest.mark.asyncio
    async def test_hop_seq_values_are_sequential_from_one(self):
        mw, _, _ = _make_middleware()
        for i in range(3):
            await _process(mw, f"agent-{i}")
        seqs = [h["seq"] for h in mw.export_token()["chain"]]
        assert seqs == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_hop_signatures_are_verifiable(self):
        mw, _, pub = _make_middleware()
        await _process(mw, "signer-agent")
        token = mw.export_token()
        result = verify_chain(token, pub)
        assert result.valid

    @pytest.mark.asyncio
    async def test_call_next_is_called_during_process(self):
        mw, _, _ = _make_middleware()
        ctx = FakeChatContext(metadata={"agent_name": "a"})
        call_next = AsyncMock()
        await mw.process(ctx, call_next)
        call_next.assert_awaited_once()


# ---------------------------------------------------------------------------
# max_hops enforcement
# ---------------------------------------------------------------------------

class TestMaxHopsEnforcement:
    @pytest.mark.asyncio
    async def test_chain_capped_at_max_hops(self):
        mw, _, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=2))
        for i in range(5):
            await _process(mw, f"agent-{i}")
        assert len(mw.export_token()["chain"]) == 2

    @pytest.mark.asyncio
    async def test_chain_does_not_grow_beyond_max_hops(self):
        mw, _, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=1))
        await _process(mw, "first")
        await _process(mw, "second")
        await _process(mw, "third")
        assert len(mw.export_token()["chain"]) == 1


# ---------------------------------------------------------------------------
# _function_middleware — scope enforcement
# ---------------------------------------------------------------------------

class TestFunctionMiddlewareScopeEnforcement:
    @pytest.mark.asyncio
    async def test_none_authorized_tools_allows_any_tool(self):
        mw, _, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=None))
        await _process(mw)
        call_next = AsyncMock()
        ctx = FakeFunctionContext(function=FakeFunctionInfo(name="any_tool"))
        await mw._function_middleware(ctx, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unauthorized_tool_recorded_as_violation(self):
        mw, _, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["allowed_tool"]),
        )
        await _process(mw)
        await _function_middleware_call(mw, "forbidden_tool")
        token = mw.export_token()
        violations = (
            token.get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert len(violations) >= 1
        assert any(v.get("tool") == "forbidden_tool" for v in violations)

    @pytest.mark.asyncio
    async def test_strict_mode_raises_on_unauthorized_tool(self):
        mw, _, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["allowed_tool"]),
            strict=True,
        )
        await _process(mw)
        with pytest.raises(HDPScopeViolationError):
            await _function_middleware_call(mw, "forbidden_tool")

    @pytest.mark.asyncio
    async def test_strict_mode_does_not_raise_on_authorized_tool(self):
        mw, _, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["safe_tool"]),
            strict=True,
        )
        await _process(mw)
        # Must not raise
        await _function_middleware_call(mw, "safe_tool")


# ---------------------------------------------------------------------------
# export_token_json()
# ---------------------------------------------------------------------------

class TestExportTokenJson:
    def test_returns_none_when_no_token_issued(self):
        mw, _, _ = _make_middleware()
        assert mw.export_token_json() is None

    @pytest.mark.asyncio
    async def test_returns_parseable_json_string_after_process(self):
        mw, _, _ = _make_middleware()
        await _process(mw)
        raw = mw.export_token_json()
        assert raw is not None
        parsed = json.loads(raw)
        assert parsed["hdp"] == "0.1"


# ---------------------------------------------------------------------------
# Bad key — graceful failure (non-blocking)
# ---------------------------------------------------------------------------

class TestBadKeyGracefulFailure:
    @pytest.mark.asyncio
    async def test_bad_key_does_not_raise(self):
        mw = HdpMiddleware(
            signing_key=b"\x00" * 5,
            session_id="s",
            principal=HdpPrincipal(id="u", id_type="opaque"),
            scope=ScopePolicy(intent="x"),
        )
        ctx = FakeChatContext(metadata={"agent_name": "bad-key-agent"})
        # Should not raise — non-blocking design
        await mw.process(ctx, AsyncMock())
        assert mw.export_token() is None
