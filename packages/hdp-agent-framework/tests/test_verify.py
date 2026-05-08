# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""Unit tests for verify_chain() — pure verification layer tests.

These tests build tokens directly with _crypto primitives and do NOT use
HdpMiddleware, so they are independent of the middleware.py implementation.
Most tests here can pass before Task 4 is complete.
"""

from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hdp_agent_framework._crypto import sign_hop, sign_root
from hdp_agent_framework.verify import verify_chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_key() -> tuple[bytes, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub


def _build_root_token(
    priv_bytes: bytes,
    session_id: str = "test-session",
    expires_offset_ms: int = 24 * 60 * 60 * 1000,
    kid: str = "default",
) -> dict:
    """Build and sign a root token dict."""
    now = int(time.time() * 1000)
    unsigned: dict = {
        "hdp": "0.1",
        "header": {
            "token_id": str(uuid.uuid4()),
            "issued_at": now,
            "expires_at": now + expires_offset_ms,
            "session_id": session_id,
            "version": "0.1",
        },
        "principal": {
            "id": "user@test.com",
            "id_type": "email",
        },
        "scope": {
            "intent": "Test intent",
            "data_classification": "internal",
            "network_egress": True,
            "persistence": False,
        },
        "chain": [],
    }
    signature = sign_root(unsigned, priv_bytes, kid)
    return {**unsigned, "signature": signature}


def _append_hop(token: dict, priv_bytes: bytes, agent_id: str) -> dict:
    """Return a new token dict with one more signed hop appended."""
    seq = len(token["chain"]) + 1
    now = int(time.time() * 1000)
    unsigned_hop: dict = {
        "seq": seq,
        "agent_id": agent_id,
        "agent_type": "sub-agent",
        "timestamp": now,
        "action_summary": f"hop {seq}",
        "parent_hop": seq - 1,
    }
    cumulative = [*token["chain"], unsigned_hop]
    hop_sig = sign_hop(cumulative, token["signature"]["value"], priv_bytes)
    signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
    new_chain = [*token["chain"], signed_hop]
    return {**token, "chain": new_chain}


# ---------------------------------------------------------------------------
# Valid chain
# ---------------------------------------------------------------------------

class TestValidChain:
    def test_root_only_chain_is_valid(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        result = verify_chain(token, pub)
        assert result.valid
        assert result.hop_count == 0
        assert result.violations == []

    def test_valid_two_hop_chain(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-alpha")
        token = _append_hop(token, priv, "agent-beta")
        result = verify_chain(token, pub)
        assert result.valid
        assert result.hop_count == 2
        assert result.violations == []

    def test_hop_count_matches_chain_length(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        for i in range(4):
            token = _append_hop(token, priv, f"agent-{i}")
        result = verify_chain(token, pub)
        assert result.hop_count == 4


# ---------------------------------------------------------------------------
# Tampered root signature
# ---------------------------------------------------------------------------

class TestTamperedRootSignature:
    def test_tampered_root_sig_is_invalid(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token["signature"]["value"] = token["signature"]["value"][:-4] + "XXXX"
        result = verify_chain(token, pub)
        assert result.valid is False

    def test_tampered_root_sig_mentions_root_in_violation(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token["signature"]["value"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result = verify_chain(token, pub)
        assert any("Root" in v for v in result.violations)


# ---------------------------------------------------------------------------
# Tampered hop signature
# ---------------------------------------------------------------------------

class TestTamperedHopSignature:
    def test_tampered_hop_sig_is_invalid(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-one")
        token["chain"][0]["hop_signature"] = "AAAA"
        result = verify_chain(token, pub)
        assert result.valid is False

    def test_tampered_second_hop_sig_is_invalid(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-one")
        token = _append_hop(token, priv, "agent-two")
        token["chain"][1]["hop_signature"] = "AAAA"
        result = verify_chain(token, pub)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Wrong public key
# ---------------------------------------------------------------------------

class TestWrongPublicKey:
    def test_wrong_key_fails_root_verification(self):
        priv, _ = _generate_key()
        _, other_pub = _generate_key()
        token = _build_root_token(priv)
        result = verify_chain(token, other_pub)
        assert result.valid is False

    def test_wrong_key_with_hops_still_fails(self):
        priv, _ = _generate_key()
        _, other_pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-x")
        result = verify_chain(token, other_pub)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Empty chain
# ---------------------------------------------------------------------------

class TestEmptyChain:
    def test_empty_chain_depth_is_zero(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        result = verify_chain(token, pub)
        assert result.depth == 0


# ---------------------------------------------------------------------------
# Expired token
# ---------------------------------------------------------------------------

class TestExpiredToken:
    def test_expired_token_has_violation(self):
        priv, pub = _generate_key()
        # expires_at 1 second in the past
        token = _build_root_token(priv, expires_offset_ms=-1000)
        result = verify_chain(token, pub)
        assert any("expired" in v.lower() for v in result.violations)

    def test_expired_token_valid_flag_is_false(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv, expires_offset_ms=-1000)
        result = verify_chain(token, pub)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Raw public key bytes accepted
# ---------------------------------------------------------------------------

class TestRawPublicKeyBytes:
    def test_verify_accepts_raw_32_byte_public_key(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        raw_bytes = pub.public_bytes_raw()
        result = verify_chain(token, raw_bytes)
        assert result.valid

    def test_verify_raw_bytes_catches_wrong_key(self):
        priv, _ = _generate_key()
        _, other_pub = _generate_key()
        token = _build_root_token(priv)
        result = verify_chain(token, other_pub.public_bytes_raw())
        assert result.valid is False

    def test_raw_bytes_with_hops_verifies_correctly(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "raw-agent")
        result = verify_chain(token, pub.public_bytes_raw())
        assert result.valid
