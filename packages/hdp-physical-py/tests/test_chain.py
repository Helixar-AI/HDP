"""Tests for Mermaid chain diagram generator."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_physical.builder import EdtBuilder
from hdp_physical.chain import generate_mermaid_diagram
from hdp_physical.signer import sign_edt
from hdp_physical.types import AuthorizationDecision, IrreversibilityClass


async def _make_signed_edt(*, max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class3_prohibited=True):
    pk = Ed25519PrivateKey.generate()
    edt = (
        EdtBuilder()
        .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
        .set_action_scope(permitted_actions=[], excluded_zones=[], max_force_n=45.0, max_velocity_ms=0.5)
        .set_irreversibility(max_class=max_class, class3_prohibited=class3_prohibited)
        .set_policy_attestation(policy_hash="sha256-abc", training_run_id="run-1", sim_validated=True)
        .set_delegation_scope()
        .build()
    )
    return await sign_edt(edt, pk, "chain-kid")


def _approved_decision(action_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT) -> AuthorizationDecision:
    return AuthorizationDecision(
        approved=True,
        classification=action_class,
        reason="All checks passed",
        edt_valid=True,
        blocked_at=None,
    )


def _blocked_decision(blocked_at: str, action_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL) -> AuthorizationDecision:
    return AuthorizationDecision(
        approved=False,
        classification=action_class,
        reason=f"Blocked at {blocked_at}",
        edt_valid=True,
        blocked_at=blocked_at,
    )


class TestGenerateMermaidDiagram:
    async def test_returns_string(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert isinstance(diagram, str)

    async def test_starts_with_flowchart(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert diagram.startswith("flowchart TD")

    async def test_approved_contains_approved_class(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert ":::approved" in diagram
        assert ":::blocked" not in diagram

    async def test_blocked_contains_blocked_class(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _blocked_decision("class3_prohibited"))
        assert ":::blocked" in diagram

    async def test_blocked_shows_blocked_at_label(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _blocked_decision("signature"))
        assert "signature" in diagram

    async def test_contains_platform_id(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "aloha_v2" in diagram

    async def test_contains_kid(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "chain-kid" in diagram

    async def test_contains_human_principal_node(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "Human Principal" in diagram

    async def test_contains_guard_node(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "PreExecutionGuard" in diagram

    async def test_approved_contains_execute_edge(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "execute" in diagram

    async def test_blocked_does_not_contain_execute_edge(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _blocked_decision("class_ceiling"))
        assert "execute" not in diagram

    async def test_custom_action_label(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision(), action_label="pick box gently")
        assert "pick box gently" in diagram

    async def test_classdefs_present(self):
        signed = await _make_signed_edt()
        diagram = generate_mermaid_diagram(signed, _approved_decision())
        assert "classDef approved" in diagram
        assert "classDef blocked" in diagram
