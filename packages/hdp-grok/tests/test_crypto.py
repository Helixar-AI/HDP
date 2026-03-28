"""Tests for hdp-grok crypto layer."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_grok._crypto import extend_token_chain, issue_root_token, verify_token_with_key


def _make_key() -> bytes:
    """Generate a fresh Ed25519 private key (raw 32 bytes)."""
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _pub_bytes(priv_bytes: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes_raw()


class TestCrypto:
    def test_issue_root_token_structure(self):
        key = _make_key()
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", ["read"], 3600)
        assert token["hdp"] == "0.1"
        assert token["header"]["session_id"] == "sess-1"
        assert token["principal"]["id"] == "user@x.com"
        assert token["chain"] == []
        assert "signature" in token
        assert token["signature"]["alg"] == "Ed25519"

    def test_root_token_verifies(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], 3600)
        result = verify_token_with_key(json.dumps(token), pub)
        assert result["valid"] is True
        assert result["hop_count"] == 0
        assert result["expired"] is False

    def test_tampered_token_fails_verification(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], 3600)
        token["principal"]["id"] = "attacker@evil.com"
        result = verify_token_with_key(json.dumps(token), pub)
        assert result["valid"] is False

    def test_extend_chain_adds_hop(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], 3600)
        token2 = extend_token_chain(token, key, "k1", "agent-A", [])
        assert len(token2["chain"]) == 1
        assert token2["chain"][0]["agent_id"] == "agent-A"
        assert token2["chain"][0]["seq"] == 1
        result = verify_token_with_key(json.dumps(token2), pub)
        assert result["valid"] is True
        assert result["hop_count"] == 1

    def test_expired_token_flagged(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=-1)
        result = verify_token_with_key(json.dumps(token), pub)
        assert result["expired"] is True
