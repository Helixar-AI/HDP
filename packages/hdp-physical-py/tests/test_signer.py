"""Tests for EdtToken signing and verification."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_physical.types import (
    ActionScope,
    DelegationScope,
    EdtToken,
    EmbodimentSpec,
    IrreversibilityClass,
    IrreversibilitySpec,
    PolicyAttestation,
    SignedEdt,
)
from hdp_physical.signer import canonicalize_edt, sign_edt, verify_edt

VECTORS = Path(__file__).parent / "vectors"


def _make_edt() -> EdtToken:
    return EdtToken(
        embodiment=EmbodimentSpec(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A"),
        action_scope=ActionScope(
            permitted_actions=["pick", "place"],
            excluded_zones=[],
            max_force_n=45.0,
            max_velocity_ms=0.5,
        ),
        irreversibility=IrreversibilitySpec(
            max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            class2_requires_confirmation=True,
            class3_prohibited=True,
        ),
        policy_attestation=PolicyAttestation(
            policy_hash="sha256-abc",
            training_run_id="run-1",
            sim_validated=True,
        ),
        delegation_scope=DelegationScope(
            allow_fleet_delegation=False,
            max_delegation_depth=1,
            sub_agent_whitelist=[],
        ),
    )


class TestCanonicalizeEdt:
    def test_deterministic(self):
        edt = _make_edt()
        assert canonicalize_edt(edt) == canonicalize_edt(edt)

    def test_sorted_keys(self):
        canonical = canonicalize_edt(_make_edt())
        # Keys should be sorted — "action_scope" before "delegation_scope" etc.
        idx_action = canonical.index('"action_scope"')
        idx_delegation = canonical.index('"delegation_scope"')
        assert idx_action < idx_delegation

    def test_no_whitespace(self):
        canonical = canonicalize_edt(_make_edt())
        assert "  " not in canonical
        assert "\n" not in canonical


class TestSignAndVerify:
    @pytest.fixture
    def keypair(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    async def test_sign_returns_signed_edt(self, keypair):
        pk, pub = keypair
        edt = _make_edt()
        signed = await sign_edt(edt, pk, "test-kid")
        assert signed.alg == "Ed25519"
        assert signed.kid == "test-kid"
        assert len(signed.signature) > 0

    async def test_verify_valid_signature(self, keypair):
        pk, pub = keypair
        signed = await sign_edt(_make_edt(), pk, "k1")
        assert await verify_edt(signed, pub) is True

    async def test_verify_rejects_tampered_payload(self, keypair):
        pk, pub = keypair
        signed = await sign_edt(_make_edt(), pk, "k1")
        # Tamper with the EDT
        tampered_edt = _make_edt()
        tampered_edt.embodiment.platform_id = "evil_bot"
        tampered = SignedEdt(edt=tampered_edt, signature=signed.signature, kid=signed.kid, alg=signed.alg)
        assert await verify_edt(tampered, pub) is False

    async def test_verify_rejects_wrong_key(self, keypair):
        pk, pub = keypair
        other_pk = Ed25519PrivateKey.generate()
        other_pub = other_pk.public_key()
        signed = await sign_edt(_make_edt(), pk, "k1")
        assert await verify_edt(signed, other_pub) is False

    async def test_verify_rejects_garbage_signature(self, keypair):
        _, pub = keypair
        signed = SignedEdt(edt=_make_edt(), signature="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", kid="k", alg="Ed25519")
        assert await verify_edt(signed, pub) is False

    async def test_verify_vector_invalid_sig(self):
        """The edt-invalid-sig vector must fail verification with any key."""
        raw = json.loads((VECTORS / "edt-invalid-sig.json").read_text())
        signed = SignedEdt.model_validate(raw)
        pub = Ed25519PrivateKey.generate().public_key()
        assert await verify_edt(signed, pub) is False
