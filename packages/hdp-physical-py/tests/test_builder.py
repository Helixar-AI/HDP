"""Tests for EdtBuilder."""

import pytest

from hdp_physical.builder import EdtBuilder
from hdp_physical.types import EdtToken, IrreversibilityClass


def _full_builder() -> EdtBuilder:
    return (
        EdtBuilder()
        .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
        .set_action_scope(permitted_actions=["pick", "place"], excluded_zones=[], max_force_n=45.0, max_velocity_ms=0.5)
        .set_irreversibility(
            max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            class2_requires_confirmation=True,
            class3_prohibited=True,
        )
        .set_policy_attestation(policy_hash="sha256-abc", training_run_id="run-1", sim_validated=True)
        .set_delegation_scope(allow_fleet_delegation=False, max_delegation_depth=1, sub_agent_whitelist=[])
    )


class TestEdtBuilder:
    def test_build_returns_edt_token(self):
        edt = _full_builder().build()
        assert isinstance(edt, EdtToken)

    def test_embodiment_fields(self):
        edt = _full_builder().build()
        assert edt.embodiment.agent_type == "robot_arm"
        assert edt.embodiment.platform_id == "aloha_v2"
        assert edt.embodiment.workspace_scope == "zone_A"

    def test_action_scope_fields(self):
        edt = _full_builder().build()
        assert "pick" in edt.action_scope.permitted_actions
        assert edt.action_scope.max_force_n == 45.0
        assert edt.action_scope.max_velocity_ms == 0.5

    def test_irreversibility_fields(self):
        edt = _full_builder().build()
        assert edt.irreversibility.max_class == IrreversibilityClass.REVERSIBLE_WITH_EFFORT
        assert edt.irreversibility.class3_prohibited is True

    def test_policy_attestation_fields(self):
        edt = _full_builder().build()
        assert edt.policy_attestation.sim_validated is True

    def test_delegation_scope_defaults(self):
        edt = _full_builder().build()
        assert edt.delegation_scope.allow_fleet_delegation is False
        assert edt.delegation_scope.sub_agent_whitelist == []

    def test_missing_section_raises(self):
        with pytest.raises(ValueError, match="missing required sections"):
            EdtBuilder().build()

    def test_partial_missing_raises(self):
        with pytest.raises(ValueError, match="action_scope"):
            (
                EdtBuilder()
                .set_embodiment(agent_type="robot_arm", platform_id="p1", workspace_scope="z1")
                .build()
            )

    def test_fluent_chaining_returns_builder(self):
        b = EdtBuilder()
        b2 = b.set_embodiment(agent_type="arm", platform_id="p", workspace_scope="z")
        assert b2 is b

    def test_sub_agent_whitelist_defaults_to_empty(self):
        b = (
            EdtBuilder()
            .set_embodiment(agent_type="arm", platform_id="p", workspace_scope="z")
            .set_action_scope(permitted_actions=[], excluded_zones=[], max_force_n=10, max_velocity_ms=0.1)
            .set_irreversibility(max_class=IrreversibilityClass.REVERSIBLE)
            .set_policy_attestation(policy_hash="h", training_run_id="r", sim_validated=False)
            .set_delegation_scope()
        )
        edt = b.build()
        assert edt.delegation_scope.sub_agent_whitelist == []
