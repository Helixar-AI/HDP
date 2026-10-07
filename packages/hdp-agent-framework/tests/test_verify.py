# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""Unit tests for verify_chain() — pure verification layer tests.

These tests build tokens directly with _crypto primitives and do NOT use
HdpMiddleware, so they are independent of the middleware.py implementation.
Most tests here can pass before Task 4 is complete.
"""

from __future__ import annotations

import time
import json
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
        token["signature"]["value"] = "A" * 86
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
        token["chain"][0]["hop_signature"] = "A" * 86
        result = verify_chain(token, pub)
        assert result.valid is False

    def test_tampered_second_hop_sig_is_invalid(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-one")
        token = _append_hop(token, priv, "agent-two")
        token["chain"][1]["hop_signature"] = "A" * 86
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
    def test_hop_at_expiry_is_recorded_without_affecting_validity(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token["header"]["issued_at"] = 100
        token["header"]["expires_at"] = 200
        token["signature"] = sign_root(token, priv, "default")
        unsigned_hop = {
            "seq": 1,
            "agent_id": "after-period-agent",
            "agent_type": "custom-role",
            "timestamp": 200,
            "action_summary": "record at expiry boundary",
            "parent_hop": 0,
        }
        signature = sign_hop([unsigned_hop], token["signature"]["value"], priv)
        token["chain"] = [{**unsigned_hop, "hop_signature": signature}]

        result = verify_chain(token, pub)
        assert result.valid is True
        assert result.violations == []
        assert result.recorded_after_period == [1]

    def test_version_failure_precedes_root_signature_failure(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token["hdp"] = "0.2"
        token["signature"]["value"] = "A" * 86

        result = verify_chain(token, pub)
        assert result.valid is False
        assert len(result.violations) == 1
        assert "Step 1" in result.violations[0]

    def test_input_validation_precedes_version_check(self):
        priv, pub = _generate_key()
        token = _append_hop(_build_root_token(priv), priv, "agent-one")
        token["hdp"] = "0.2"
        token["chain"][0]["agent_type"] = 123

        result = verify_chain(token, pub)

        assert result.valid is False
        assert result.violations == [
            "Step 0: Input validation failed: chain[0].agent_type must be a string"
        ]

    def test_structure_failure_stops_before_hop_signatures(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token = _append_hop(token, priv, "agent-one")
        token["chain"][0]["seq"] = 2
        token["chain"][0]["hop_signature"] = "A" * 86

        result = verify_chain(token, pub)

        assert result.valid is False
        assert len(result.violations) == 1
        assert "Step 3" in result.violations[0]
        assert result.hop_results == []

    def test_recorded_depth_failure_is_step_five(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        token["scope"]["max_hops"] = 1
        token["signature"] = sign_root(token, priv, "default")
        token = _append_hop(token, priv, "agent-one")
        token = _append_hop(token, priv, "agent-two")

        result = verify_chain(token, pub)

        assert result.valid is False
        assert len(result.violations) == 1
        assert "Step 5" in result.violations[0]
        assert len(result.hop_results) == 2


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


class TestSerializedInputValidation:
    def test_duplicate_member_string_fails_step_zero_and_clean_string_verifies(self):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        clean_json = json.dumps(token)

        clean_result = verify_chain(clean_json, pub)
        duplicate_json = clean_json[:-1] + ',"hdp":"0.1"}'
        duplicate_result = verify_chain(duplicate_json, pub)

        assert clean_result.valid is True
        assert duplicate_result.valid is False
        assert duplicate_result.violations == [
            "Step 0: Input validation failed: duplicate JSON object member 'hdp'"
        ]

    @pytest.mark.parametrize(
        "invalid_value,expected_error",
        [
            (9007199254740993, "token.principal.metadata.value integer must be exactly representable"),
            (None, "scope.max_hops must be a positive integer"),
        ],
    )
    def test_section_three_invalid_dict_fails_step_zero(self, invalid_value, expected_error):
        priv, pub = _generate_key()
        token = _build_root_token(priv)
        if invalid_value is None:
            token["scope"]["max_hops"] = invalid_value
        else:
            token["principal"]["metadata"] = {"value": invalid_value}

        result = verify_chain(token, pub)

        assert result.valid is False
        assert len(result.violations) == 1
        assert result.violations[0].startswith("Step 0: Input validation failed: ")
        assert expected_error in result.violations[0]

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
