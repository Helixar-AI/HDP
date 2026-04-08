"""Tests for offline chain verification — ported and extended from hdp-crewai."""

from __future__ import annotations

import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from llama_index.callbacks.hdp import verify_chain
from llama_index.callbacks.hdp._crypto import sign_root, sign_hop


def _generate_key():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key()


def _issue_token(key: bytes, pub_key=None, session_id="s1", expired=False, max_hops=None) -> dict:
    import uuid
    now = int(time.time() * 1000)
    expires_at = now - 1000 if expired else now + 86400000
    scope: dict = {"intent": "test", "data_classification": "internal", "network_egress": True, "persistence": False}
    if max_hops is not None:
        scope["max_hops"] = max_hops
    unsigned = {
        "hdp": "0.1",
        "header": {
            "token_id": str(uuid.uuid4()),
            "issued_at": now,
            "expires_at": expires_at,
            "session_id": session_id,
            "version": "0.1",
        },
        "principal": {"id": "user@test.com", "id_type": "email"},
        "scope": scope,
        "chain": [],
    }
    sig = sign_root(unsigned, key, "k1")
    return {**unsigned, "signature": sig}


def _add_hop(token: dict, key: bytes, action: str) -> dict:
    import time
    chain = token.get("chain", [])
    seq = len(chain) + 1
    unsigned_hop = {
        "seq": seq,
        "agent_id": "test-agent",
        "agent_type": "tool-executor",
        "timestamp": int(time.time() * 1000),
        "action_summary": action,
        "parent_hop": seq - 1,
    }
    cumulative = [*chain, unsigned_hop]
    hop_sig = sign_hop(cumulative, token["signature"]["value"], key)
    return {**token, "chain": [*chain, {**unsigned_hop, "hop_signature": hop_sig}]}


class TestVerifyChain:
    def test_empty_chain_valid(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid
        assert result.hop_count == 0

    def test_chain_with_hops_valid(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        token = _add_hop(token, key, "tool_call: web_search")
        token = _add_hop(token, key, "tool_call: retriever")
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid
        assert result.hop_count == 2

    def test_accepts_raw_public_key_bytes(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid

    def test_tampered_root_sig_fails(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        token["signature"]["value"] = token["signature"]["value"][:-4] + "XXXX"
        result = verify_chain(token, pub.public_bytes_raw())
        assert not result.valid
        assert any("Root signature" in v for v in result.violations)

    def test_tampered_hop_sig_fails(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        token = _add_hop(token, key, "action")
        token["chain"][0]["hop_signature"] = "AAAA"
        result = verify_chain(token, pub.public_bytes_raw())
        assert not result.valid

    def test_wrong_public_key_fails(self):
        key, _ = _generate_key()
        _, other_pub = _generate_key()
        token = _issue_token(key)
        result = verify_chain(token, other_pub.public_bytes_raw())
        assert not result.valid

    def test_expired_token_flagged(self):
        key, pub = _generate_key()
        token = _issue_token(key, expired=True)
        result = verify_chain(token, pub.public_bytes_raw())
        assert any("expired" in v.lower() for v in result.violations)

    def test_max_hops_exceeded_flagged(self):
        key, pub = _generate_key()
        # max_hops must be set at issuance time so root sig covers it
        token = _issue_token(key, max_hops=1)
        token = _add_hop(token, key, "hop 1")
        token = _add_hop(token, key, "hop 2")
        result = verify_chain(token, pub.public_bytes_raw())
        assert any("max_hops" in v for v in result.violations)

    def test_hop_results_detail(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        token = _add_hop(token, key, "action a")
        token = _add_hop(token, key, "action b")
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid
        assert len(result.hop_results) == 2
        assert all(hr.valid for hr in result.hop_results)

    def test_depth_property(self):
        key, pub = _generate_key()
        token = _issue_token(key)
        for i in range(3):
            token = _add_hop(token, key, f"hop {i}")
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.depth == 3
