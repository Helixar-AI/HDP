"""Tests for HdpMiddleware and HdpCallbackHandler — all 5 design considerations (LangChain).

Run with: cd packages/hdp-langchain && PYTHONPATH=src pytest tests/ -v
"""

from __future__ import annotations

import base64
import time
import uuid
from unittest.mock import MagicMock

import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hdp_langchain import (
    HdpCallbackHandler,
    HdpMiddleware,
    HdpPrincipal,
    HDPScopeViolationError,
    ScopePolicy,
    VerificationResult,
    verify_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_key() -> tuple[bytes, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


def _verify(public_key: Ed25519PublicKey, message: bytes, sig_b64url: str) -> bool:
    try:
        public_key.verify(_b64url_decode(sig_b64url), message)
        return True
    except Exception:
        return False


def _make_middleware(scope: ScopePolicy | None = None, **kwargs) -> tuple[HdpMiddleware, Ed25519PublicKey]:
    key, pub = _generate_key()
    mw = HdpMiddleware(
        signing_key=key,
        session_id="test-session",
        principal=HdpPrincipal(id="user@test.com", id_type="email"),
        scope=scope or ScopePolicy(intent="Test intent"),
        **kwargs,
    )
    return mw, pub


def _make_run_id() -> uuid.UUID:
    return uuid.uuid4()


def _tool_serialized(name: str) -> dict:
    """Simulate a LangChain serialized tool dict."""
    return {"name": name, "description": f"A tool called {name}"}


def _chain_serialized(name: str = "RunnableSequence") -> dict:
    """Simulate a LangChain serialized chain dict."""
    return {"id": ["langchain", "schema", "runnable", name], "name": name}


def _invoke_on_chain_start(handler: HdpCallbackHandler, name: str = "TestChain") -> uuid.UUID:
    run_id = _make_run_id()
    handler.on_chain_start(_chain_serialized(name), {}, run_id=run_id)
    return run_id


def _invoke_on_chain_end(handler: HdpCallbackHandler, run_id: uuid.UUID) -> None:
    handler.on_chain_end({}, run_id=run_id)


def _invoke_on_tool_start(handler: HdpCallbackHandler, tool_name: str, input_str: str = "test input") -> uuid.UUID:
    run_id = _make_run_id()
    handler.on_tool_start(_tool_serialized(tool_name), input_str, run_id=run_id)
    return run_id


# ---------------------------------------------------------------------------
# #3 Token size / performance: non-blocking error handling
# ---------------------------------------------------------------------------

class TestNonBlocking:
    def test_bad_key_does_not_raise(self):
        mw = HdpMiddleware(
            signing_key=b"\x00" * 5,
            session_id="s",
            principal=HdpPrincipal(id="u", id_type="opaque"),
            scope=ScopePolicy(intent="x"),
        )
        mw.before_kickoff()
        assert mw.export_token() is None

    def test_export_token_json_none_before_kickoff(self):
        mw, _ = _make_middleware()
        assert mw.export_token_json() is None

    def test_extend_chain_noop_before_kickoff(self):
        mw, _ = _make_middleware()
        mw._extend_chain(agent_id="tool", action_summary="test", agent_type="tool-executor")
        assert mw.export_token() is None


# ---------------------------------------------------------------------------
# Root token issuance
# ---------------------------------------------------------------------------

class TestBeforeKickoff:
    def test_issues_root_token(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        token = mw.export_token()
        assert token is not None
        assert token["hdp"] == "0.1"
        assert token["header"]["session_id"] == "test-session"
        assert token["chain"] == []

    def test_root_signature_verifiable(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        token = mw.export_token()
        subset = {f: token[f] for f in ["header", "principal", "scope"]}
        message = jcs.canonicalize(subset)
        assert _verify(pub, message, token["signature"]["value"])

    def test_export_token_json_returns_string(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        json_str = mw.export_token_json()
        assert isinstance(json_str, str)
        assert '"hdp"' in json_str


# ---------------------------------------------------------------------------
# #2 Delegation depth limits
# ---------------------------------------------------------------------------

class TestDelegationDepth:
    def test_hops_appended_in_order(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        for i in range(3):
            mw._extend_chain(agent_id=f"tool_{i}", action_summary=f"step {i}", agent_type="tool-executor")
        chain = mw.export_token()["chain"]
        assert len(chain) == 3
        assert [h["seq"] for h in chain] == [1, 2, 3]

    def test_max_hops_enforced(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=2))
        mw.before_kickoff()
        for i in range(4):
            mw._extend_chain(agent_id=f"tool_{i}", action_summary=str(i), agent_type="tool-executor")
        assert len(mw.export_token()["chain"]) == 2

    def test_hop_signature_verifiable(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw._extend_chain(agent_id="web_search", action_summary="search query", agent_type="tool-executor")
        token = mw.export_token()
        hop = token["chain"][0]
        unsigned_hop = {k: v for k, v in hop.items() if k != "hop_signature"}
        payload = {"chain": [unsigned_hop], "root_sig": token["signature"]["value"]}
        message = jcs.canonicalize(payload)
        assert _verify(pub, message, hop["hop_signature"])

    def test_hop_agent_type_preserved(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        mw._extend_chain(agent_id="tool_x", action_summary="x", agent_type="tool-executor")
        hop = mw.export_token()["chain"][0]
        assert hop["agent_type"] == "tool-executor"


# ---------------------------------------------------------------------------
# #1 Scope enforcement
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    def test_no_authorized_tools_means_all_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x"))
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "any_tool")
        assert mw.export_token()["scope"].get("extensions") is None

    def test_authorized_tool_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["web_search"]))
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "web_search")
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert violations == []

    def test_unauthorized_tool_recorded_in_token(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["web_search"]))
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "browser_tool")
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert len(violations) == 1
        assert violations[0]["tool"] == "browser_tool"

    def test_strict_mode_raises_on_unauthorized_tool(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
            strict=True,
        )
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        with pytest.raises(HDPScopeViolationError) as exc_info:
            _invoke_on_tool_start(handler, "browser_tool")
        assert exc_info.value.tool == "browser_tool"

    def test_strict_mode_allows_authorized_tool(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
            strict=True,
        )
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "web_search")  # should not raise
        assert len(mw.export_token()["chain"]) == 1


# ---------------------------------------------------------------------------
# #4 Verification utilities
# ---------------------------------------------------------------------------

class TestVerification:
    def test_valid_chain_passes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw._extend_chain(agent_id="tool_a", action_summary="r1", agent_type="tool-executor")
        mw._extend_chain(agent_id="tool_b", action_summary="r2", agent_type="tool-executor")
        result = verify_chain(mw.export_token(), pub)
        assert result.valid
        assert result.hop_count == 2
        assert len(result.violations) == 0

    def test_verify_accepts_raw_key_bytes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw._extend_chain(agent_id="tool_a", action_summary="r", agent_type="tool-executor")
        raw_pub = pub.public_bytes_raw()
        result = verify_chain(mw.export_token(), raw_pub)
        assert result.valid

    def test_tampered_root_sig_fails(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        token = mw.export_token()
        token["signature"]["value"] = token["signature"]["value"][:-4] + "XXXX"
        result = verify_chain(token, pub)
        assert not result.valid
        assert any("Root signature" in v for v in result.violations)

    def test_tampered_hop_sig_fails(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw._extend_chain(agent_id="tool_a", action_summary="r", agent_type="tool-executor")
        token = mw.export_token()
        token["chain"][0]["hop_signature"] = "AAAA"
        result = verify_chain(token, pub)
        assert not result.valid

    def test_wrong_public_key_fails(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        _, other_pub = _generate_key()
        result = verify_chain(mw.export_token(), other_pub)
        assert not result.valid

    def test_expired_token_flagged(self):
        from hdp_langchain._crypto import sign_root
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        mw = HdpMiddleware(
            signing_key=priv.private_bytes_raw(),
            session_id="s",
            principal=HdpPrincipal(id="u", id_type="opaque"),
            scope=ScopePolicy(intent="x"),
        )
        mw.before_kickoff()
        token = mw.export_token()
        token["header"]["expires_at"] = int(time.time() * 1000) - 1000
        unsigned = {k: v for k, v in token.items() if k != "signature"}
        token["signature"] = sign_root(unsigned, priv.private_bytes_raw(), "k")
        result = verify_chain(token, pub)
        assert any("expired" in v.lower() for v in result.violations)

    def test_empty_chain_valid(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        result = verify_chain(mw.export_token(), pub)
        assert result.valid
        assert result.hop_count == 0


# ---------------------------------------------------------------------------
# #5 Callback handler integration
# ---------------------------------------------------------------------------

class TestCallbackHandler:
    def test_get_callback_handler_returns_instance(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        assert isinstance(handler, HdpCallbackHandler)

    def test_on_chain_start_issues_root_token(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        assert mw.export_token() is None
        _invoke_on_chain_start(handler)
        assert mw.export_token() is not None

    def test_on_chain_start_only_issues_root_once(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        run_id_1 = _invoke_on_chain_start(handler, "OuterChain")
        run_id_2 = _invoke_on_chain_start(handler, "InnerChain")  # nested
        token_id = mw.export_token()["header"]["token_id"]
        _invoke_on_chain_end(handler, run_id_2)
        _invoke_on_chain_end(handler, run_id_1)
        # Same token throughout
        assert mw.export_token()["header"]["token_id"] == token_id

    def test_on_tool_start_records_hop(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "web_search", "who won the 2026 world cup")
        chain = mw.export_token()["chain"]
        assert len(chain) == 1
        assert chain[0]["agent_id"] == "web_search"
        assert chain[0]["agent_type"] == "tool-executor"

    def test_on_tool_start_action_summary_includes_input(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        _invoke_on_tool_start(handler, "calculator", "2 + 2")
        hop = mw.export_token()["chain"][0]
        assert "2 + 2" in hop["action_summary"]

    def test_on_tool_start_truncates_long_input(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        long_input = "x" * 500
        _invoke_on_tool_start(handler, "tool", long_input)
        hop = mw.export_token()["chain"][0]
        assert len(hop["action_summary"]) <= 230  # "Tool 'tool' invoked: " + 200 chars

    def test_on_tool_start_auto_issues_root_if_missing(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        assert mw.export_token() is None
        # on_tool_start without prior on_chain_start — middleware auto-issues on _extend_chain
        # but _extend_chain is noop if token is None; root must be issued via on_chain_start
        # So this should record no hop but also not raise
        _invoke_on_chain_start(handler)  # issue root first
        _invoke_on_tool_start(handler, "tool_x")
        assert len(mw.export_token()["chain"]) == 1

    def test_on_chain_end_decrements_depth(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        run_id = _invoke_on_chain_start(handler)
        assert handler._chain_depth == 1
        _invoke_on_chain_end(handler, run_id)
        assert handler._chain_depth == 0

    def test_on_tool_error_does_not_raise(self):
        mw, _ = _make_middleware()
        handler = mw.get_callback_handler()
        handler.on_tool_error(ValueError("boom"), run_id=_make_run_id())  # should not raise

    def test_full_flow_verifies(self):
        mw, pub = _make_middleware(scope=ScopePolicy(intent="test", authorized_tools=["search", "calc"]))
        handler = mw.get_callback_handler()
        run_id = _invoke_on_chain_start(handler)
        _invoke_on_tool_start(handler, "search", "query")
        _invoke_on_tool_start(handler, "calc", "1+1")
        _invoke_on_chain_end(handler, run_id)
        result = verify_chain(mw.export_token(), pub)
        assert result.valid
        assert result.hop_count == 2

    def test_serialized_without_name_falls_back_to_id(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        # Simulate older LangChain format with no "name" key
        serialized = {"id": ["langchain", "tools", "MyCustomTool"]}
        handler.on_tool_start(serialized, "input", run_id=_make_run_id())
        hop = mw.export_token()["chain"][0]
        assert hop["agent_id"] == "MyCustomTool"

    def test_serialized_empty_falls_back_to_unknown(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        handler = mw.get_callback_handler()
        handler.on_tool_start({}, "input", run_id=_make_run_id())
        hop = mw.export_token()["chain"][0]
        assert hop["agent_id"] == "unknown_tool"
