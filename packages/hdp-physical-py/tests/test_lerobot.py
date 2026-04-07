"""Tests for LeRobot adapter."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_physical.builder import EdtBuilder
from hdp_physical.lerobot import (
    BlockedActionError,
    LeRobotActionAdapter,
    LeRobotGuardedPolicy,
    _action_dict_to_robot_action,
)
from hdp_physical.signer import sign_edt
from hdp_physical.types import IrreversibilityClass


async def _make_adapter(
    *,
    max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
    class3_prohibited=True,
    max_force_n=45.0,
    max_velocity_ms=0.5,
):
    pk = Ed25519PrivateKey.generate()
    edt = (
        EdtBuilder()
        .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
        .set_action_scope(
            permitted_actions=["pick", "place"],
            excluded_zones=["danger_zone"],
            max_force_n=max_force_n,
            max_velocity_ms=max_velocity_ms,
        )
        .set_irreversibility(
            max_class=max_class,
            class3_prohibited=class3_prohibited,
        )
        .set_policy_attestation(policy_hash="sha256-x", training_run_id="r1", sim_validated=True)
        .set_delegation_scope()
        .build()
    )
    signed = await sign_edt(edt, pk, "test-kid")
    return LeRobotActionAdapter(signed_edt=signed, public_key=pk.public_key())


class TestActionDictToRobotAction:
    def test_basic_fields(self):
        a = _action_dict_to_robot_action({"force_n": 10.0, "velocity_ms": 0.3, "task": "pick box"})
        assert a.force_n == 10.0
        assert a.velocity_ms == 0.3
        assert a.description == "pick box"

    def test_alias_keys(self):
        a = _action_dict_to_robot_action({"force": 5.0, "velocity": 0.2})
        assert a.force_n == 5.0
        assert a.velocity_ms == 0.2

    def test_missing_optional_fields(self):
        a = _action_dict_to_robot_action({})
        assert a.force_n is None
        assert a.velocity_ms is None
        assert a.description == "lerobot_action"

    def test_zone_field(self):
        a = _action_dict_to_robot_action({"zone": "zone_B"})
        assert a.zone == "zone_B"


class TestLeRobotActionAdapter:
    async def test_approves_safe_action(self):
        adapter = await _make_adapter()
        decision = await adapter.authorize({"task": "pick box", "force_n": 5.0, "velocity_ms": 0.1})
        assert decision.approved

    async def test_blocks_class3_action(self):
        adapter = await _make_adapter(class3_prohibited=True)
        decision = await adapter.authorize({"task": "crush object", "force_n": 45.0})
        assert not decision.approved
        assert decision.blocked_at == "class3_prohibited"

    async def test_blocks_excluded_zone(self):
        adapter = await _make_adapter()
        decision = await adapter.authorize({"task": "move", "force_n": 5.0, "zone": "danger_zone"})
        assert not decision.approved
        assert decision.blocked_at == "excluded_zone"


class TestLeRobotGuardedPolicy:
    async def test_passes_through_safe_action(self):
        pk = Ed25519PrivateKey.generate()
        edt = (
            EdtBuilder()
            .set_embodiment(agent_type="robot_arm", platform_id="p", workspace_scope="z")
            .set_action_scope(permitted_actions=[], excluded_zones=[], max_force_n=45.0, max_velocity_ms=0.5)
            .set_irreversibility(max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT)
            .set_policy_attestation(policy_hash="h", training_run_id="r", sim_validated=True)
            .set_delegation_scope()
            .build()
        )
        signed = await sign_edt(edt, pk, "k")

        class FakePolicy:
            def select_action(self, obs):
                return {"task": "pick box gently", "force_n": 5.0, "velocity_ms": 0.1}

        guarded = LeRobotGuardedPolicy(FakePolicy(), signed, pk.public_key())
        result = guarded.select_action({})
        assert result["force_n"] == 5.0

    async def test_raises_on_blocked_action(self):
        pk = Ed25519PrivateKey.generate()
        edt = (
            EdtBuilder()
            .set_embodiment(agent_type="robot_arm", platform_id="p", workspace_scope="z")
            .set_action_scope(permitted_actions=[], excluded_zones=[], max_force_n=45.0, max_velocity_ms=0.5)
            .set_irreversibility(max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class3_prohibited=True)
            .set_policy_attestation(policy_hash="h", training_run_id="r", sim_validated=True)
            .set_delegation_scope()
            .build()
        )
        signed = await sign_edt(edt, pk, "k")

        class MaliciousPolicy:
            def select_action(self, obs):
                return {"task": "crush object", "force_n": 45.0}

        guarded = LeRobotGuardedPolicy(MaliciousPolicy(), signed, pk.public_key())
        with pytest.raises(BlockedActionError) as exc_info:
            guarded.select_action({})
        assert exc_info.value.decision.blocked_at == "class3_prohibited"
