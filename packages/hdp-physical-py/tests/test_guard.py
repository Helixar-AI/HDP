"""Tests for PreExecutionGuard — six-step authorization."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_physical.builder import EdtBuilder
from hdp_physical.guard import PreExecutionGuard
from hdp_physical.signer import sign_edt
from hdp_physical.types import IrreversibilityClass, RobotAction, SignedEdt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair():
    pk = Ed25519PrivateKey.generate()
    return pk, pk.public_key()


async def _make_signed_edt(
    *,
    max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
    class3_prohibited=True,
    excluded_zones=None,
    max_force_n=45.0,
    max_velocity_ms=0.5,
    kid="test-kid",
    private_key=None,
):
    if private_key is None:
        private_key = Ed25519PrivateKey.generate()
    edt = (
        EdtBuilder()
        .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
        .set_action_scope(
            permitted_actions=["pick", "place", "move"],
            excluded_zones=excluded_zones or [],
            max_force_n=max_force_n,
            max_velocity_ms=max_velocity_ms,
        )
        .set_irreversibility(
            max_class=max_class,
            class2_requires_confirmation=False,
            class3_prohibited=class3_prohibited,
        )
        .set_policy_attestation(policy_hash="sha256-abc", training_run_id="run-1", sim_validated=True)
        .set_delegation_scope(allow_fleet_delegation=False, max_delegation_depth=1, sub_agent_whitelist=[])
        .build()
    )
    return await sign_edt(edt, private_key, kid), private_key.public_key()


guard = PreExecutionGuard()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestApproved:
    async def test_safe_action_approved(self):
        signed, pub = await _make_signed_edt()
        decision = await guard.authorize(
            RobotAction(description="pick box from left", force_n=5.0, velocity_ms=0.2),
            signed,
            pub,
        )
        assert decision.approved
        assert decision.edt_valid
        assert decision.blocked_at is None

    async def test_accepts_dict_action(self):
        signed, pub = await _make_signed_edt()
        decision = await guard.authorize(
            {"description": "place box", "force_n": 3.0, "velocity_ms": 0.1},
            signed,
            pub,
        )
        assert decision.approved


class TestSignatureCheck:
    async def test_blocks_invalid_signature(self):
        signed, _ = await _make_signed_edt()
        wrong_pub = Ed25519PrivateKey.generate().public_key()
        decision = await guard.authorize(
            RobotAction(description="pick box", force_n=5.0),
            signed,
            wrong_pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "signature"
        assert not decision.edt_valid

    async def test_blocks_tampered_signature(self):
        signed, pub = await _make_signed_edt()
        tampered = SignedEdt(
            edt=signed.edt,
            signature="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            kid=signed.kid,
            alg=signed.alg,
        )
        decision = await guard.authorize(RobotAction(description="pick box"), tampered, pub)
        assert decision.blocked_at == "signature"


class TestClass3Prohibition:
    async def test_blocks_class3_when_prohibited(self):
        signed, pub = await _make_signed_edt(class3_prohibited=True)
        decision = await guard.authorize(
            RobotAction(description="crush the object", force_n=45.0),
            signed,
            pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "class3_prohibited"

    async def test_allows_class3_when_not_prohibited(self):
        signed, pub = await _make_signed_edt(
            max_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
            class3_prohibited=False,
        )
        # Use a class-3 description but the guard should not block at class3_prohibited
        # (it may still block at class_ceiling if max_class < 3, but here max_class=3)
        decision = await guard.authorize(
            RobotAction(description="crush object", force_n=45.0),
            signed,
            pub,
        )
        # blocked_at is NOT class3_prohibited
        assert decision.blocked_at != "class3_prohibited"


class TestClassCeiling:
    async def test_blocks_class2_when_ceiling_is_class1(self):
        signed, pub = await _make_signed_edt(
            max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            class3_prohibited=True,
        )
        decision = await guard.authorize(
            RobotAction(description="press-fit component into slot"),
            signed,
            pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "class_ceiling"

    async def test_allows_class1_with_class1_ceiling(self):
        signed, pub = await _make_signed_edt(max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT)
        decision = await guard.authorize(
            RobotAction(description="pick box gently", force_n=5.0, velocity_ms=0.1),
            signed,
            pub,
        )
        assert decision.approved


class TestExcludedZone:
    async def test_blocks_excluded_zone(self):
        signed, pub = await _make_signed_edt(excluded_zones=["danger_zone"])
        decision = await guard.authorize(
            RobotAction(description="move to zone", zone="danger_zone"),
            signed,
            pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "excluded_zone"

    async def test_allows_permitted_zone(self):
        signed, pub = await _make_signed_edt(excluded_zones=["danger_zone"])
        decision = await guard.authorize(
            RobotAction(description="pick box", force_n=5.0, zone="zone_A"),
            signed,
            pub,
        )
        assert decision.approved


class TestForceLimitCheck:
    async def test_blocks_action_exceeding_force_limit(self):
        # Use max_force_n=20 so force_n=25 (Class 1, not Class 3) exceeds the EDT limit
        pk = Ed25519PrivateKey.generate()
        signed, pub = await _make_signed_edt(
            max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            max_force_n=20.0,
            private_key=pk,
        )
        decision = await guard.authorize(
            RobotAction(description="move box", force_n=25.0, velocity_ms=0.2),
            signed,
            pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "force_limit"

    async def test_allows_action_within_force_limit(self):
        signed, pub = await _make_signed_edt(max_force_n=45.0)
        decision = await guard.authorize(
            RobotAction(description="pick box", force_n=10.0, velocity_ms=0.1),
            signed,
            pub,
        )
        assert decision.approved


class TestVelocityLimitCheck:
    async def test_blocks_action_exceeding_velocity_limit(self):
        # velocity=0.3 < 90% of 0.5 (0.45) → Class 1; exceeds EDT max_velocity_ms=0.2
        signed, pub = await _make_signed_edt(max_velocity_ms=0.2)
        decision = await guard.authorize(
            RobotAction(description="move box", force_n=5.0, velocity_ms=0.3),
            signed,
            pub,
        )
        assert not decision.approved
        assert decision.blocked_at == "velocity_limit"

    async def test_allows_action_within_velocity_limit(self):
        signed, pub = await _make_signed_edt(max_velocity_ms=0.5)
        decision = await guard.authorize(
            RobotAction(description="pick box", force_n=5.0, velocity_ms=0.2),
            signed,
            pub,
        )
        assert decision.approved
