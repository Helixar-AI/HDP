"""Tests for HdpMiddleware — all 5 design considerations (AutoGen).

Run with: cd packages/hdp-autogen && PYTHONPATH=src pytest tests/ -v
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import MagicMock

import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hdp_autogen import (
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


class FakeAgent:
    """Simulates autogen.ConversableAgent with register_hook support."""

    def __init__(self, name: str = "agent-1"):
        self.name = name
        self._hooks: dict[str, list] = {}

    def register_hook(self, hookable_method: str, hook: object) -> None:
        self._hooks.setdefault(hookable_method, []).append(hook)

    def fire_send(self, message: str, recipient: object = None, silent: bool = False) -> str:
        """Simulate firing process_message_before_send hooks."""
        result = message
        for hook in self._hooks.get("process_message_before_send", []):
            result = hook(self, result, recipient, silent)
        return result

    def fire_receive(self, message: object, sender: object = None, silent: bool = False) -> object:
        """Simulate firing process_last_received_message hooks."""
        result = message
        for hook in self._hooks.get("process_last_received_message", []):
            result = hook(sender, result, self, silent)
        return result


class FakeGroupChat:
    """Simulates autogen.GroupChat."""

    def __init__(self, agents: list):
        self.agents = agents
        self.messages: list = []


class FakeGroupChatManager:
    """Simulates autogen.GroupChatManager."""

    def __init__(self, groupchat: FakeGroupChat):
        self._groupchat = groupchat
        self._run_chat_called = False

    def run_chat(self, messages: list | None = None) -> list:
        self._run_chat_called = True
        return messages or []


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

    def test_on_message_send_without_kickoff_auto_issues(self):
        mw, _ = _make_middleware()
        agent = FakeAgent("A")
        mw.on_message_send(agent, "hello", None)
        # Token should be auto-issued
        assert mw.export_token() is not None

    def test_export_token_json_none_before_kickoff(self):
        mw, _ = _make_middleware()
        assert mw.export_token_json() is None


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


# ---------------------------------------------------------------------------
# #2 Delegation depth limits
# ---------------------------------------------------------------------------

class TestDelegationDepth:
    def test_hops_appended_in_order(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        for i in range(3):
            agent = FakeAgent(f"Agent{i}")
            mw.on_message_send(agent, f"step {i}", None)
        chain = mw.export_token()["chain"]
        assert len(chain) == 3
        assert [h["seq"] for h in chain] == [1, 2, 3]

    def test_max_hops_enforced(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=2))
        mw.before_kickoff()
        for i in range(4):
            agent = FakeAgent(f"A{i}")
            mw.on_message_send(agent, str(i), None)
        assert len(mw.export_token()["chain"]) == 2

    def test_hop_signature_verifiable(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        agent = FakeAgent("Agent1")
        mw.on_message_send(agent, "output", None)
        token = mw.export_token()
        hop = token["chain"][0]
        unsigned_hop = {k: v for k, v in hop.items() if k != "hop_signature"}
        payload = {"chain": [unsigned_hop], "root_sig": token["signature"]["value"]}
        message = jcs.canonicalize(payload)
        assert _verify(pub, message, hop["hop_signature"])


# ---------------------------------------------------------------------------
# #1 Scope enforcement
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    def test_no_tool_calls_no_violation(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["web_search"]))
        mw.before_kickoff()
        mw.on_message_receive(None, "plain text message", None)
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert violations == []

    def test_authorized_tool_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["web_search"]))
        mw.before_kickoff()
        msg = {"content": "searching", "tool_calls": [{"function": {"name": "web_search"}}]}
        mw.on_message_receive(None, msg, None)
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
        msg = {"content": "browsing", "tool_calls": [{"function": {"name": "browser_tool"}}]}
        mw.on_message_receive(None, msg, None)
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert len(violations) == 1
        assert violations[0]["tool"] == "browser_tool"

    def test_strict_mode_raises(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
            strict=True,
        )
        mw.before_kickoff()
        msg = {"content": "browsing", "tool_calls": [{"function": {"name": "browser_tool"}}]}
        with pytest.raises(HDPScopeViolationError) as exc_info:
            mw.on_message_receive(None, msg, None)
        assert exc_info.value.tool == "browser_tool"

    def test_no_authorized_tools_means_all_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x"))
        mw.before_kickoff()
        msg = {"content": "anything", "tool_calls": [{"function": {"name": "any_tool"}}]}
        mw.on_message_receive(None, msg, None)
        assert mw.export_token()["scope"].get("extensions") is None

    def test_legacy_function_call_format(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["web_search"]),
            strict=True,
        )
        mw.before_kickoff()
        msg = {"content": "browsing", "function_call": {"name": "browser_tool"}}
        with pytest.raises(HDPScopeViolationError):
            mw.on_message_receive(None, msg, None)


# ---------------------------------------------------------------------------
# #4 Verification utilities
# ---------------------------------------------------------------------------

class TestVerification:
    def test_valid_chain_passes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_message_send(FakeAgent("A1"), "r1", None)
        mw.on_message_send(FakeAgent("A2"), "r2", None)
        token = mw.export_token()
        result = verify_chain(token, pub)
        assert result.valid
        assert result.hop_count == 2
        assert len(result.violations) == 0

    def test_verify_accepts_raw_key_bytes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_message_send(FakeAgent("A"), "r", None)
        token = mw.export_token()
        raw_pub = pub.public_bytes_raw()
        result = verify_chain(token, raw_pub)
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
        mw.on_message_send(FakeAgent("A"), "r", None)
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
        from hdp_autogen._crypto import sign_root
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
        # Force expiry in the past and re-sign
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
# #5 GroupChat integration — configure()
# ---------------------------------------------------------------------------

class TestConfigureConversableAgent:
    def test_attaches_hooks_to_agent(self):
        mw, _ = _make_middleware()
        agent = FakeAgent("test-agent")
        mw.configure(agent)
        assert len(agent._hooks.get("process_message_before_send", [])) == 1
        assert len(agent._hooks.get("process_last_received_message", [])) == 1

    def test_send_hook_extends_chain(self):
        mw, _ = _make_middleware()
        agent = FakeAgent("test-agent")
        mw.configure(agent)
        agent.fire_send("hello world")
        token = mw.export_token()
        assert token is not None
        assert len(token["chain"]) == 1
        assert token["chain"][0]["agent_id"] == "test-agent"

    def test_receive_hook_checks_scope(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["allowed"]),
            strict=True,
        )
        mw.before_kickoff()
        agent = FakeAgent("test-agent")
        mw.configure(agent)
        msg = {"content": "call", "tool_calls": [{"function": {"name": "forbidden"}}]}
        with pytest.raises(HDPScopeViolationError):
            agent.fire_receive(msg)


class TestConfigureGroupChatManager:
    def test_wraps_run_chat(self):
        agents = [FakeAgent("a1"), FakeAgent("a2")]
        gc = FakeGroupChat(agents=agents)
        manager = FakeGroupChatManager(groupchat=gc)
        mw, _ = _make_middleware()
        mw.configure(manager)

        # run_chat should issue root token
        manager.run_chat(messages=[])
        assert mw.export_token() is not None
        assert manager._run_chat_called

    def test_attaches_hooks_to_groupchat_agents(self):
        agents = [FakeAgent("a1"), FakeAgent("a2")]
        gc = FakeGroupChat(agents=agents)
        manager = FakeGroupChatManager(groupchat=gc)
        mw, _ = _make_middleware()
        mw.configure(manager)

        # Both agents should have hooks
        for agent in agents:
            assert len(agent._hooks.get("process_message_before_send", [])) == 1

    def test_configure_list_of_agents(self):
        agents = [FakeAgent("a1"), FakeAgent("a2"), FakeAgent("a3")]
        mw, _ = _make_middleware()
        mw.configure(agents)
        for agent in agents:
            assert len(agent._hooks.get("process_message_before_send", [])) == 1

    def test_speaker_turns_recorded_as_hops(self):
        agents = [FakeAgent("researcher"), FakeAgent("reviewer")]
        gc = FakeGroupChat(agents=agents)
        manager = FakeGroupChatManager(groupchat=gc)
        mw, pub = _make_middleware()
        mw.configure(manager)
        manager.run_chat()

        # Simulate speaker turns
        agents[0].fire_send("I found relevant papers")
        agents[1].fire_send("The methodology looks sound")
        agents[0].fire_send("Adding citations now")

        token = mw.export_token()
        assert len(token["chain"]) == 3
        assert token["chain"][0]["agent_id"] == "researcher"
        assert token["chain"][1]["agent_id"] == "reviewer"
        assert token["chain"][2]["agent_id"] == "researcher"

        # Full chain should verify
        result = verify_chain(token, pub)
        assert result.valid


class TestConfigureUnrecognised:
    def test_unrecognised_target_logs_warning(self):
        mw, _ = _make_middleware()
        mw.configure(object())  # should not raise
        assert mw.export_token() is None


# ---------------------------------------------------------------------------
# Message extraction
# ---------------------------------------------------------------------------

class TestMessageExtraction:
    def test_string_message_content(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        mw.on_message_send(FakeAgent("A"), "hello world", None)
        hop = mw.export_token()["chain"][0]
        assert hop["action_summary"] == "hello world"

    def test_dict_message_content(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        mw.on_message_send(FakeAgent("A"), {"content": "dict message"}, None)
        hop = mw.export_token()["chain"][0]
        assert hop["action_summary"] == "dict message"

    def test_long_message_truncated(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        long_msg = "x" * 500
        mw.on_message_send(FakeAgent("A"), long_msg, None)
        hop = mw.export_token()["chain"][0]
        assert len(hop["action_summary"]) == 200
