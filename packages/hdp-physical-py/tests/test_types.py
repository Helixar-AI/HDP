"""Tests for core HDP-P types."""

import json
from pathlib import Path

import pytest

from hdp_physical.types import (
    ActionScope,
    AuthorizationDecision,
    ClassificationResult,
    DelegationScope,
    EdtToken,
    EmbodimentSpec,
    IrreversibilityClass,
    IrreversibilitySpec,
    PolicyAttestation,
    RobotAction,
    SignedEdt,
)

VECTORS = Path(__file__).parent / "vectors"


class TestIrreversibilityClass:
    def test_values(self):
        assert IrreversibilityClass.REVERSIBLE == 0
        assert IrreversibilityClass.REVERSIBLE_WITH_EFFORT == 1
        assert IrreversibilityClass.IRREVERSIBLE_NORMALLY == 2
        assert IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL == 3

    def test_ordering(self):
        assert IrreversibilityClass.REVERSIBLE < IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL

    def test_from_int(self):
        assert IrreversibilityClass(2) == IrreversibilityClass.IRREVERSIBLE_NORMALLY


class TestEdtToken:
    def _make_edt(self) -> EdtToken:
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

    def test_roundtrip_json(self):
        edt = self._make_edt()
        data = edt.model_dump()
        edt2 = EdtToken.model_validate(data)
        assert edt2 == edt

    def test_max_class_is_int_enum(self):
        edt = self._make_edt()
        assert isinstance(edt.irreversibility.max_class, IrreversibilityClass)
        assert edt.irreversibility.max_class == 1


class TestVectorFile:
    def test_edt_valid_vector_parses(self):
        raw = json.loads((VECTORS / "edt-valid.json").read_text())
        signed = SignedEdt.model_validate(raw)
        assert signed.alg == "Ed25519"
        assert signed.kid
        assert len(signed.signature) > 0

    def test_edt_invalid_sig_vector_parses(self):
        raw = json.loads((VECTORS / "edt-invalid-sig.json").read_text())
        signed = SignedEdt.model_validate(raw)
        assert signed.signature  # just parses — guard will reject at runtime


class TestRobotAction:
    def test_minimal(self):
        a = RobotAction(description="query sensor")
        assert a.force_n is None
        assert a.zone is None

    def test_full(self):
        a = RobotAction(description="pick box", force_n=10.0, velocity_ms=0.3, zone="zone_A")
        assert a.force_n == 10.0


class TestAuthorizationDecision:
    def test_approved(self):
        d = AuthorizationDecision(
            approved=True,
            classification=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            reason="all checks passed",
            edt_valid=True,
            blocked_at=None,
        )
        assert d.approved
        assert d.blocked_at is None

    def test_blocked(self):
        d = AuthorizationDecision(
            approved=False,
            classification=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
            reason="class3_prohibited",
            edt_valid=True,
            blocked_at="class3_prohibited",
        )
        assert not d.approved
        assert d.blocked_at == "class3_prohibited"
