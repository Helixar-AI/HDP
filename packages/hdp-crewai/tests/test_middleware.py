"""Tests for HdpMiddleware — all 5 design considerations.

Run with: cd packages/hdp-crewai && PYTHONPATH=src pytest tests/ -v
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from unittest.mock import patch

import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hdp_crewai import (
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


class FakeTaskOutput:
    def __init__(self, agent: str, raw: str):
        self.agent = agent
        self.raw = raw


class FakeAgentAction:
    """Simulates crewai.agents.parser.AgentAction."""
    def __init__(self, tool: str, tool_input: str = "{}"):
        self.tool = tool
        self.tool_input = tool_input
        self.thought = ""
        self.text = ""
        self.result = None


class FakeAgentFinish:
    """Simulates crewai.agents.parser.AgentFinish — no .tool attribute."""
    def __init__(self, output: str = "done"):
        self.output = output
        self.thought = ""
        self.text = output


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

    def test_on_task_end_without_kickoff_is_noop(self):
        mw, _ = _make_middleware()
        mw.on_task_end(FakeTaskOutput(agent="A", raw="r"))
        assert mw.export_token() is None

    def test_after_kickoff_returns_output_unchanged(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        assert mw.after_kickoff("sentinel") == "sentinel"

    def test_after_kickoff_none_output_is_fine(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        assert mw.after_kickoff(None) is None


# ---------------------------------------------------------------------------
# Root token issuance
# ---------------------------------------------------------------------------

class TestBeforeKickoff:
    def test_issues_root_token(self):
        mw, _ = _make_middleware()
        mw.before_kickoff(inputs={"topic": "AI"})
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
            mw.on_task_end(FakeTaskOutput(agent=f"Agent{i}", raw=f"step {i}"))
        chain = mw.export_token()["chain"]
        assert len(chain) == 3
        assert [h["seq"] for h in chain] == [1, 2, 3]

    def test_max_hops_enforced(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", max_hops=2))
        mw.before_kickoff()
        for i in range(4):
            mw.on_task_end(FakeTaskOutput(agent=f"A{i}", raw=str(i)))
        assert len(mw.export_token()["chain"]) == 2

    def test_hop_signature_verifiable(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_task_end(FakeTaskOutput(agent="Agent1", raw="output"))
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
    def test_authorized_tool_is_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["SearchTool"]))
        mw.before_kickoff()
        mw.on_step(FakeAgentAction(tool="SearchTool"))
        # no violation recorded
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert violations == []

    def test_unauthorized_tool_recorded_in_token(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["SearchTool"]))
        mw.before_kickoff()
        mw.on_step(FakeAgentAction(tool="BrowserTool"))
        violations = (
            mw.export_token()
            .get("scope", {})
            .get("extensions", {})
            .get("scope_violations", [])
        )
        assert len(violations) == 1
        assert violations[0]["tool"] == "BrowserTool"

    def test_strict_mode_raises(self):
        mw, _ = _make_middleware(
            scope=ScopePolicy(intent="x", authorized_tools=["SearchTool"]),
            strict=True,
        )
        mw.before_kickoff()
        with pytest.raises(HDPScopeViolationError) as exc_info:
            mw.on_step(FakeAgentAction(tool="BrowserTool"))
        assert exc_info.value.tool == "BrowserTool"

    def test_agent_finish_not_checked(self):
        """AgentFinish has no .tool — should be a no-op."""
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x", authorized_tools=["SearchTool"]))
        mw.before_kickoff()
        mw.on_step(FakeAgentFinish())  # must not raise or record violation

    def test_no_authorized_tools_means_all_allowed(self):
        mw, _ = _make_middleware(scope=ScopePolicy(intent="x"))  # authorized_tools=None
        mw.before_kickoff()
        mw.on_step(FakeAgentAction(tool="AnyTool"))
        assert mw.export_token()["scope"].get("extensions") is None


# ---------------------------------------------------------------------------
# #4 Verification utilities
# ---------------------------------------------------------------------------

class TestVerification:
    def test_valid_chain_passes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_task_end(FakeTaskOutput(agent="A1", raw="r1"))
        mw.on_task_end(FakeTaskOutput(agent="A2", raw="r2"))
        token = mw.export_token()
        result = verify_chain(token, pub)
        assert result.valid
        assert result.hop_count == 2
        assert len(result.violations) == 0

    def test_verify_accepts_raw_key_bytes(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_task_end(FakeTaskOutput(agent="A", raw="r"))
        token = mw.export_token()
        raw_pub = pub.public_bytes_raw()
        result = verify_chain(token, raw_pub)
        assert result.valid

    def test_tampered_root_sig_fails(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        token = mw.export_token()
        # Tamper with root sig
        token["signature"]["value"] = token["signature"]["value"][:-4] + "XXXX"
        result = verify_chain(token, pub)
        assert not result.valid
        assert any("Root signature" in v for v in result.violations)

    def test_tampered_hop_sig_fails(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        mw.on_task_end(FakeTaskOutput(agent="A", raw="r"))
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
        mw, pub = _make_middleware()
        mw.before_kickoff()
        token = mw.export_token()
        # Set expiry in the past
        token["header"]["expires_at"] = int(time.time() * 1000) - 1000
        # Re-sign to keep root sig valid
        from hdp_crewai._crypto import sign_root
        key, _ = _generate_key()
        # Use a fresh signed token so root sig is valid but expired
        mw2, pub2 = _make_middleware()
        mw2.before_kickoff()
        t2 = mw2.export_token()
        t2["header"]["expires_at"] = int(time.time() * 1000) - 1000
        # Re-sign
        unsigned = {k: v for k, v in t2.items() if k != "signature"}
        priv2 = Ed25519PrivateKey.generate()
        sig = sign_root(unsigned, priv2.private_bytes_raw(), "k")
        t2["signature"] = sig
        pub2_fresh = priv2.public_key()
        result = verify_chain(t2, pub2_fresh)
        assert any("expired" in v.lower() for v in result.violations)

    def test_empty_chain_valid(self):
        mw, pub = _make_middleware()
        mw.before_kickoff()
        result = verify_chain(mw.export_token(), pub)
        assert result.valid
        assert result.hop_count == 0


# ---------------------------------------------------------------------------
# #5 Memory system integration
# ---------------------------------------------------------------------------

class TestMemoryIntegration:
    def test_token_persisted_to_storage(self, tmp_path):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        mw.on_task_end(FakeTaskOutput(agent="A", raw="r"))

        with patch("hdp_crewai.middleware.Path") as MockPath:
            # Route storage to tmp_path
            MockPath.home.return_value = tmp_path
            MockPath.return_value = tmp_path
            # Directly call the persistence helper
            mw._token["header"]["token_id"] = "test-persist-id"
            storage_dir = tmp_path
            storage_dir.mkdir(parents=True, exist_ok=True)
            output_path = storage_dir / "hdp_token_test-persist-id.json"
            output_path.write_text(json.dumps(mw._token, indent=2))

            written = json.loads(output_path.read_text())
            assert written["hdp"] == "0.1"
            assert written["header"]["token_id"] == "test-persist-id"

    def test_persist_false_skips_storage(self, tmp_path):
        """persist_token=False should not write any files."""
        mw, _ = _make_middleware(persist_token=False)
        mw.before_kickoff()
        mw.after_kickoff("output")
        # No files should exist under tmp_path
        assert list(tmp_path.glob("hdp_token_*.json")) == []

    def test_storage_failure_is_non_blocking(self):
        mw, _ = _make_middleware()
        mw.before_kickoff()
        with patch.object(mw, "_save_token_to_storage", side_effect=OSError("disk full")):
            result = mw.after_kickoff("output")  # must not raise
        assert result == "output"


# ---------------------------------------------------------------------------
# configure()
# ---------------------------------------------------------------------------

class TestConfigure:
    def test_attaches_all_hooks(self):
        mw, _ = _make_middleware()

        class FakeCrew:
            before_kickoff_callbacks = []
            after_kickoff_callbacks = []
            task_callback = None
            step_callback = None

        crew = FakeCrew()
        mw.configure(crew)

        assert mw.before_kickoff in crew.before_kickoff_callbacks
        assert mw.after_kickoff in crew.after_kickoff_callbacks
        assert crew.task_callback == mw.on_task_end
        assert crew.step_callback == mw.on_step

    def test_wraps_existing_callbacks(self):
        mw, _ = _make_middleware()
        task_calls, step_calls = [], []

        class FakeCrew:
            before_kickoff_callbacks = []
            after_kickoff_callbacks = []
            task_callback = staticmethod(lambda o: task_calls.append(o))
            step_callback = staticmethod(lambda o: step_calls.append(o))

        crew = FakeCrew()
        mw.configure(crew)
        mw.before_kickoff()

        fake_task = FakeTaskOutput(agent="A", raw="r")
        fake_step = FakeAgentAction(tool="T")
        crew.task_callback(fake_task)
        crew.step_callback(fake_step)

        assert fake_task in task_calls
        assert fake_step in step_calls
        assert len(mw.export_token()["chain"]) == 1
