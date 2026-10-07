"""Tests for HdpCallbackHandler — legacy CallbackManager integration."""

from __future__ import annotations

import time
from types import SimpleNamespace
import pytest
import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from llama_index.core.callbacks import CBEventType, EventPayload
from llama_index.callbacks.hdp import (
    HdpCallbackHandler,
    HdpInstrumentationHandler,
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

    def test_invalid_principal_id_type_fails_at_handler_construction(self):
        key, _ = _generate_key()

        with pytest.raises(ValueError, match="principal.id_type"):
            HdpCallbackHandler(
                signing_key=key,
                principal=HdpPrincipal(id="u", id_type="x-a\rb"),
                scope=ScopePolicy(intent="test"),
            )

    def test_export_token_matches_context(self):
        handler, _, _ = _make_handler()
        handler.start_trace("s2")
        exported = handler.export_token()
        internal = get_token()
        assert exported == internal
        assert exported is not internal

        exported["header"]["session_id"] = "corrupted"
        exported["signature"]["value"] = "corrupted"
        assert get_token()["header"]["session_id"] == "s2"
        assert get_token()["signature"]["value"] != "corrupted"

    @pytest.mark.parametrize("expires_in_ms", [0, -1, True, 1.5, 2**53])
    def test_invalid_ttl_fails_at_handler_construction(self, expires_in_ms):
        with pytest.raises(ValueError, match="expires_in_ms"):
            _make_handler(expires_in_ms=expires_in_ms)

    def test_invalid_max_hops_fails_at_handler_construction(self):
        with pytest.raises(ValueError, match="max_hops must be a positive integer"):
            _make_handler(scope=ScopePolicy(intent="x", max_hops=0))


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

    def test_signing_failure_keeps_out_of_scope_event_result(self, monkeypatch, caplog):
        handler, _, _ = _make_handler(
            scope=ScopePolicy(intent="private intent", authorized_tools=["allowed"])
        )
        handler.start_trace("signing-failure")

        def fail_signing(*args, **kwargs):
            raise RuntimeError("principal and intent must not be logged")

        monkeypatch.setattr("llama_index.callbacks.hdp.callbacks.sign_hop", fail_signing)
        event_id = handler.on_event_start(
            CBEventType.FUNCTION_CALL,
            payload={EventPayload.TOOL: FakeTool("forbidden")},
            event_id="preserved-event",
        )

        assert event_id == "preserved-event"
        assert "HDP audit record append failed" in caplog.text
        assert "principal and intent must not be logged" not in caplog.text

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
        assert last_hop["action_summary"] == "observed tool output: search results here"
        assert last_hop["hop_signature"]


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
        token = get_token()
        assert token["scope"].get("extensions") is None
        assert token["chain"][-1]["agent_id"] == "llama-index-agent"
        assert token["chain"][-1]["action_summary"] == "attempted out-of-scope tool call: exec_code"
        assert token["chain"][-1]["hop_signature"]

    def test_strict_mode_is_rejected_at_construction(self):
        assert issubclass(HDPScopeViolationError, Exception)
        with pytest.raises(ValueError, match="HDP tokens are records and cannot gate actions"):
            _make_handler(
                scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
                strict=True,
            )

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

    def test_instrumentation_raise_option_is_rejected_at_construction(self):
        key, _ = _generate_key()
        with pytest.raises(ValueError, match="HDP tokens are records and cannot gate actions"):
            HdpInstrumentationHandler.init(
                signing_key=key,
                principal=HdpPrincipal(id="user@test.com", id_type="email"),
                scope=ScopePolicy(intent="x"),
                on_violation="raise",
            )

    @pytest.mark.parametrize("expires_in_ms", [0, -1, True, 1.5, 2**53])
    def test_instrumentation_rejects_invalid_ttl_at_construction(self, expires_in_ms):
        key, _ = _generate_key()
        with pytest.raises(ValueError, match="expires_in_ms"):
            HdpInstrumentationHandler.init(
                signing_key=key,
                principal=HdpPrincipal(id="user@test.com", id_type="email"),
                scope=ScopePolicy(intent="x"),
                expires_in_ms=expires_in_ms,
            )

    def test_instrumentation_rejects_invalid_max_hops_at_construction(self):
        key, _ = _generate_key()
        with pytest.raises(ValueError, match="max_hops must be a positive integer"):
            HdpInstrumentationHandler.init(
                signing_key=key,
                principal=HdpPrincipal(id="user@test.com", id_type="email"),
                scope=ScopePolicy(intent="x", max_hops=0),
            )

    def test_instrumentation_rejects_invalid_principal_id_type_at_construction(self):
        key, _ = _generate_key()
        with pytest.raises(ValueError, match="principal.id_type"):
            HdpInstrumentationHandler.init(
                signing_key=key,
                principal=HdpPrincipal(id="u", id_type="x-a\rb"),
                scope=ScopePolicy(intent="x"),
            )

    def test_instrumentation_export_is_a_defensive_deep_copy(self):
        handler, _, _ = _make_handler()
        handler.start_trace("instrumentation-export")
        instrument_handler = object.__new__(HdpInstrumentationHandler)
        exported = instrument_handler.export_token()

        exported["header"]["session_id"] = "corrupted"
        exported["signature"]["value"] = "corrupted"

        assert get_token()["header"]["session_id"] == "instrumentation-export"
        assert get_token()["signature"]["value"] != "corrupted"


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

    def test_root_validation_failure_does_not_abort_query_result(self, monkeypatch, caplog):
        handler, _, _ = _make_handler()

        def fail_validation(*args, **kwargs):
            raise RuntimeError("private root token details")

        monkeypatch.setattr("llama_index.callbacks.hdp.callbacks._validate_token_input", fail_validation)

        def run_query():
            handler.start_trace("runtime-validation-failure")
            return "query result"

        assert run_query() == "query result"
        assert get_token() is None
        assert "HDP root record issuance failed; action continues" in caplog.text
        assert "private root token details" not in caplog.text

    def test_instrumentation_root_validation_failure_does_not_abort_query_result(
        self, monkeypatch, caplog
    ):
        from llama_index.callbacks.hdp.instrumentation import HdpEventHandler

        key, _ = _generate_key()
        event_handler = HdpEventHandler(
            signing_key=key,
            principal=HdpPrincipal(id="u", id_type="opaque"),
            scope=ScopePolicy(intent="test"),
            key_id="default",
            expires_in_ms=86_400_000,
            on_token_ready=None,
        )

        def fail_validation(*args, **kwargs):
            raise RuntimeError("private root token details")

        monkeypatch.setattr(
            "llama_index.callbacks.hdp.instrumentation._validate_token_input", fail_validation
        )

        def run_query():
            event_handler._on_query_start(SimpleNamespace(id_="runtime-query"))
            return "instrumentation query result"

        assert run_query() == "instrumentation query result"
        assert get_token() is None
        assert "HDP root record issuance failed; action continues" in caplog.text
        assert "private root token details" not in caplog.text
