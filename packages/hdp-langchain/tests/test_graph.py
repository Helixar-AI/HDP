"""Tests for LangGraph node wrapper (hdp_node).

Run with: cd packages/hdp-langchain && PYTHONPATH=src pytest tests/ -v
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_langchain import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain
from hdp_langchain.graph import hdp_node


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_middleware(**kwargs) -> tuple[HdpMiddleware, object]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    mw = HdpMiddleware(
        signing_key=priv.private_bytes_raw(),
        session_id="graph-test",
        principal=HdpPrincipal(id="user@test.com", id_type="email"),
        scope=kwargs.pop("scope", ScopePolicy(intent="LangGraph test")),
        **kwargs,
    )
    return mw, pub


# ---------------------------------------------------------------------------
# Basic wrapping
# ---------------------------------------------------------------------------

class TestHdpNodeWrapper:
    def test_wrapped_node_is_called(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        called = []

        @hdp_node(mw)
        def my_node(state):
            called.append(True)
            return state

        result = my_node({"value": 1})
        assert result == {"value": 1}
        assert called == [True]

    def test_wrapped_node_records_hop(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()

        @hdp_node(mw)
        def researcher_node(state):
            return state

        researcher_node({})
        chain = mw.export_token()["chain"]
        assert len(chain) == 1
        assert chain[0]["agent_id"] == "researcher_node"
        assert chain[0]["agent_type"] == "sub-agent"

    def test_agent_id_defaults_to_function_name(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()

        @hdp_node(mw)
        def summarizer(state):
            return state

        summarizer({})
        hop = mw.export_token()["chain"][0]
        assert hop["agent_id"] == "summarizer"

    def test_explicit_agent_id_overrides_function_name(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()

        @hdp_node(mw, agent_id="custom-researcher")
        def node_fn(state):
            return state

        node_fn({})
        hop = mw.export_token()["chain"][0]
        assert hop["agent_id"] == "custom-researcher"

    def test_wrapper_syntax_without_decorator(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()

        def plain_node(state):
            return {**state, "processed": True}

        wrapped = hdp_node(mw)(plain_node)
        result = wrapped({"x": 1})
        assert result == {"x": 1, "processed": True}
        assert len(mw.export_token()["chain"]) == 1

    def test_direct_wrap_syntax(self):
        """hdp_node(middleware, fn) — function passed directly."""
        mw, _ = _make_middleware()
        mw.before_kickoff()

        def plain_node(state):
            return state

        wrapped = hdp_node(mw, plain_node)
        wrapped({})
        assert len(mw.export_token()["chain"]) == 1
        assert mw.export_token()["chain"][0]["agent_id"] == "plain_node"

    def test_functools_wraps_preserves_name(self):
        mw, _ = _make_middleware()

        @hdp_node(mw)
        def original_name(state):
            return state

        assert original_name.__name__ == "original_name"


# ---------------------------------------------------------------------------
# Multi-node graphs
# ---------------------------------------------------------------------------

class TestMultiNodeGraph:
    def test_multiple_nodes_produce_sequential_hops(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()

        @hdp_node(mw, agent_id="node-a")
        def node_a(state):
            return {**state, "a": True}

        @hdp_node(mw, agent_id="node-b")
        def node_b(state):
            return {**state, "b": True}

        @hdp_node(mw, agent_id="node-c")
        def node_c(state):
            return {**state, "c": True}

        state = {}
        state = node_a(state)
        state = node_b(state)
        state = node_c(state)

        assert state == {"a": True, "b": True, "c": True}
        chain = mw.export_token()["chain"]
        assert len(chain) == 3
        assert [h["agent_id"] for h in chain] == ["node-a", "node-b", "node-c"]
        assert [h["seq"] for h in chain] == [1, 2, 3]

    def test_full_graph_chain_verifies(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()

        @hdp_node(mw, agent_id="planner")
        def planner(state):
            return state

        @hdp_node(mw, agent_id="executor")
        def executor(state):
            return state

        @hdp_node(mw, agent_id="reviewer")
        def reviewer(state):
            return state

        planner({})
        executor({})
        reviewer({})

        result = verify_chain(mw.export_token(), pub)
        assert result.valid
        assert result.hop_count == 3

    def test_node_auto_issues_root_if_not_issued(self):
        """hdp_node calls before_kickoff if token hasn't been issued yet."""
        mw, _ = _make_middleware()
        assert mw.export_token() is None

        @hdp_node(mw)
        def first_node(state):
            return state

        first_node({})
        assert mw.export_token() is not None
        assert len(mw.export_token()["chain"]) == 1

    def test_max_hops_respected_across_nodes(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=2))
        mw.before_kickoff()

        @hdp_node(mw)
        def node(state):
            return state

        for _ in range(5):
            node({})

        assert len(mw.export_token()["chain"]) == 2
