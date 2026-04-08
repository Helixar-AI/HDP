"""Tests for HdpCallbackHandler — legacy CallbackManager integration."""

from __future__ import annotations

import time
import pytest
import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from llama_index.core.callbacks import CBEventType, EventPayload
from llama_index.callbacks.hdp import (
    HdpCallbackHandler,
    HdpPrincipal,
    HDPScopeViolationError,
    ScopePolicy,
    verify_chain,
)
from llama_index.callbacks.hdp.session import clear_token, get_token


def _generate_key():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key()


def _make_handler(scope=None, **kwargs):
    key, pub = _generate_key()
    handler = HdpCallbackHandler(
        signing_key=key,
        principal=HdpPrincipal(id="user@test.com", id_type="email"),
        scope=scope or ScopePolicy(intent="Test query"),
        **kwargs,
    )
    return handler, key, pub


class FakeTool:
    def __init__(self, name: str):
        self.name = name


class TestRootTokenIssuance:
    def setup_method(self):
        clear_token()

    def test_start_trace_issues_root_token(self):
        handler, _, _ = _make_handler()
        handler.start_trace("trace-001")
        token = get_token()
        assert token is not None
        assert token["hdp"] == "0.1"
        assert token["header"]["session_id"] == "trace-001"
        assert token["chain"] == []

    def test_start_trace_without_id_generates_session(self):
        handler, _, _ = _make_handler()
        handler.start_trace()
        token = get_token()
        assert token is not None
        assert token["header"]["session_id"]  # some UUID was generated

    def test_root_signature_is_verifiable(self):
        handler, _, pub = _make_handler()
        handler.start_trace("s1")
        token = get_token()
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid

    def test_export_token_matches_context(self):
        handler, _, _ = _make_handler()
        handler.start_trace("s2")
        assert handler.export_token() is get_token()


class TestEndTrace:
    def setup_method(self):
        clear_token()

    def test_end_trace_calls_on_token_ready(self):
        received = []
        handler, _, _ = _make_handler(on_token_ready=received.append)
        handler.start_trace("s3")
        handler.end_trace("s3")
        assert len(received) == 1
        assert received[0]["hdp"] == "0.1"

    def test_end_trace_without_token_is_noop(self):
        handler, _, _ = _make_handler()
        handler.end_trace("s3")  # no start_trace called first — must not raise


class TestToolCallHandling:
    def setup_method(self):
        clear_token()

    def _tool_start(self, handler, tool_name: str, event_id="e1"):
        handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool(tool_name)},
            event_id=event_id,
        )

    def test_tool_call_extends_chain(self):
        handler, _, _ = _make_handler()
        handler.start_trace("s4")
        self._tool_start(handler, "web_search")
        chain = get_token()["chain"]
        assert len(chain) == 1
        assert chain[0]["action_summary"] == "tool_call: web_search"

    def test_tool_call_hop_is_signed(self):
        handler, _, pub = _make_handler()
        handler.start_trace("s5")
        self._tool_start(handler, "web_search")
        result = verify_chain(get_token(), pub.public_bytes_raw())
        assert result.valid

    def test_multiple_tool_calls_build_chain(self):
        handler, _, pub = _make_handler()
        handler.start_trace("s6")
        self._tool_start(handler, "tool_a", "e1")
        self._tool_start(handler, "tool_b", "e2")
        self._tool_start(handler, "tool_c", "e3")
        chain = get_token()["chain"]
        assert len(chain) == 3
        assert [h["seq"] for h in chain] == [1, 2, 3]
        assert verify_chain(get_token(), pub.public_bytes_raw()).valid

    def test_tool_output_recorded_on_end(self):
        handler, _, _ = _make_handler()
        handler.start_trace("s7")
        self._tool_start(handler, "web_search")
        handler.on_event_end(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.FUNCTION_OUTPUT: "search results here"},
            event_id="e1",
        )
        last_hop = get_token()["chain"][-1]
        assert "tool_output_preview" in last_hop.get("metadata", {})


class TestScopeEnforcement:
    def setup_method(self):
        clear_token()

    def test_authorized_tool_no_violation(self):
        handler, _, _ = _make_handler(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"])
        )
        handler.start_trace("sv1")
        handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool("web_search")},
        )
        violations = get_token().get("scope", {}).get("extensions", {}).get("scope_violations", [])
        assert violations == []

    def test_unauthorized_tool_recorded_in_observe_mode(self):
        handler, _, _ = _make_handler(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"])
        )
        handler.start_trace("sv2")
        handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool("exec_code")},
        )
        violations = get_token()["scope"]["extensions"]["scope_violations"]
        assert len(violations) == 1
        assert violations[0]["tool"] == "exec_code"

    def test_strict_mode_raises(self):
        handler, _, _ = _make_handler(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
            strict=True,
        )
        handler.start_trace("sv3")
        with pytest.raises(HDPScopeViolationError) as exc_info:
            handler.on_event_start(
                CBEventType.FUNCTION_CALL,
                payload={EventPayload.TOOL: FakeTool("exec_code")},
            )
        assert exc_info.value.tool == "exec_code"

    def test_no_authorized_tools_means_all_allowed(self):
        handler, _, _ = _make_handler(scope=ScopePolicy(intent="x"))
        handler.start_trace("sv4")
        handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool("anything")},
        )
        extensions = get_token().get("scope", {}).get("extensions", {})
        assert "scope_violations" not in extensions

    def test_max_hops_enforced(self):
        handler, _, _ = _make_handler(scope=ScopePolicy(intent="x", max_hops=2))
        handler.start_trace("sv5")
        for i in range(5):
            handler.on_event_start(
                CBEventType.FUNCTION_CALL,
                payload={EventPayload.TOOL: FakeTool(f"tool_{i}")},
            )
        assert len(get_token()["chain"]) == 2


class TestNonBlocking:
    def setup_method(self):
        clear_token()

    def test_bad_key_does_not_raise(self):
        handler = HdpCallbackHandler(
            signing_key=b"\x00" * 5,
            principal=HdpPrincipal(id="u", id_type="opaque"),
            scope=ScopePolicy(intent="x"),
        )
        handler.start_trace("nb1")
        assert get_token() is None

    def test_events_without_token_are_noop(self):
        handler, _, _ = _make_handler()
        # No start_trace — on_event_start must not raise
        handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool("web_search")},
        )
