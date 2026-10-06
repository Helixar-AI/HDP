"""Tests for hdp-grok crypto layer."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_grok._crypto import _sign_hop, _sign_root, extend_token_chain, issue_root_token, verify_token_with_key


def _make_key() -> bytes:
    """Generate a fresh Ed25519 private key (raw 32 bytes)."""
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _pub_bytes(priv_bytes: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes_raw()


class TestCrypto:
    def test_invalid_json_keeps_legacy_violation_field(self):
        result = verify_token_with_key("not JSON", _pub_bytes(_make_key()))

        assert result["valid"] is False
        assert result["violations"] == ["invalid JSON"]
        assert result["integrity_violations"] == ["Input validation failed: invalid JSON"]
        assert result["recorded_after_period"] == []

    def test_duplicate_json_member_is_rejected(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], 3600)
        token_json = json.dumps(token)[:-1] + ',"hdp":"0.1"}'

        result = verify_token_with_key(token_json, pub)

        assert result["valid"] is False
        assert result["integrity_violations"] == [
            "Input validation failed: duplicate JSON object member 'hdp'"
        ]

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

    def test_extend_chain_does_not_record_past_max_hops(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], 3600)
        token["scope"]["max_hops"] = 1
        token["signature"] = _sign_root(token, key, "k1")
        token = extend_token_chain(token, key, "k1", "recorded-agent", [])

        result_token = extend_token_chain(token, key, "k1", "unrecorded-agent", [])

        assert len(result_token["chain"]) == 1
        assert result_token["chain"][0]["seq"] == 1
        assert result_token["chain"][0]["agent_id"] == "recorded-agent"
        result = verify_token_with_key(json.dumps(result_token), pub)
        assert result["valid"] is True

    def test_expired_token_flagged(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=3600)
        token["header"]["issued_at"] = 0
        token["header"]["expires_at"] = 1
        token["signature"] = _sign_root(token, key, "k1")
        result = verify_token_with_key(json.dumps(token), pub)
        assert result["expired"] is True
        assert result["valid"] is True
        assert result["recorded_after_period"] == []

    def test_hop_at_expiry_is_recorded_without_affecting_validity(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=3600)
        token["header"]["issued_at"] = 0
        token["header"]["expires_at"] = 1
        token["signature"] = _sign_root(token, key, "k1")
        token = extend_token_chain(token, key, "k1", "after-period-agent", [])

        result = verify_token_with_key(json.dumps(token), pub)

        assert result["valid"] is True
        assert result["expired"] is True
        assert result["recorded_after_period"] == [1]
        assert result["integrity_violations"] == []

    def test_version_failure_precedes_root_signature_failure(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=3600)
        token["hdp"] = "0.2"
        token["signature"]["value"] = "invalid"

        result = verify_token_with_key(json.dumps(token), pub)

        assert result["valid"] is False
        assert result["integrity_violations"] == ["Step 1: unsupported HDP version '0.2'"]

    def test_input_validation_precedes_version_check(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=3600)
        token = extend_token_chain(token, key, "k1", "agent-one", [])
        token["hdp"] = "0.2"
        token["chain"][0]["agent_type"] = 123

        result = verify_token_with_key(json.dumps(token), pub)

        assert result["valid"] is False
        assert result["integrity_violations"] == [
            "Input validation failed: chain[0].agent_type must be a string"
        ]

    def test_recorded_depth_failure_is_step_five(self):
        key = _make_key()
        pub = _pub_bytes(key)
        token = issue_root_token(key, "k1", "sess-1", "user@x.com", [], expires_in=3600)
        token = extend_token_chain(token, key, "k1", "agent-one", [])
        token = extend_token_chain(token, key, "k1", "agent-two", [])
        token["scope"]["max_hops"] = 1
        token["signature"] = _sign_root(token, key, "k1")
        root_sig = token["signature"]["value"]
        for index, hop in enumerate(token["chain"]):
            unsigned_hop = {field: value for field, value in hop.items() if field != "hop_signature"}
            hop["hop_signature"] = _sign_hop(
                [*token["chain"][:index], unsigned_hop], root_sig, key
            )

        result = verify_token_with_key(json.dumps(token), pub)

        assert result["valid"] is False
        assert result["integrity_violations"] == ["Step 5: chain depth 2 exceeds max_hops 1"]
