"""Core HDP-P types — EDT token structure and related enums."""

from __future__ import annotations

from enum import IntEnum
from typing import List, Optional

from pydantic import BaseModel, Field


class IrreversibilityClass(IntEnum):
    """Physical action irreversibility classification."""

    REVERSIBLE = 0
    """Sensor query, state read — fully reversible."""

    REVERSIBLE_WITH_EFFORT = 1
    """Normal pick-and-place — reversible with some effort."""

    IRREVERSIBLE_NORMALLY = 2
    """Press-fit, adhesive bond — difficult to reverse."""

    IRREVERSIBLE_AND_HARMFUL = 3
    """Crush, override safety limits — harmful and irreversible."""


class EmbodimentSpec(BaseModel):
    """Physical embodiment specification."""

    agent_type: str
    platform_id: str
    workspace_scope: str


class ActionScope(BaseModel):
    """Permitted action envelope."""

    permitted_actions: List[str] = Field(default_factory=list)
    excluded_zones: List[str] = Field(default_factory=list)
    max_force_n: float
    max_velocity_ms: float


class IrreversibilitySpec(BaseModel):
    """Irreversibility policy."""

    max_class: IrreversibilityClass
    class2_requires_confirmation: bool = False
    class3_prohibited: bool = True


class PolicyAttestation(BaseModel):
    """Model / policy provenance attestation."""

    policy_hash: str
    training_run_id: str
    sim_validated: bool = False


class DelegationScope(BaseModel):
    """Fleet / sub-agent delegation constraints."""

    allow_fleet_delegation: bool = False
    max_delegation_depth: int = 1
    sub_agent_whitelist: List[str] = Field(default_factory=list)


class EdtToken(BaseModel):
    """Embodied Delegation Token — unsigned payload."""

    embodiment: EmbodimentSpec
    action_scope: ActionScope
    irreversibility: IrreversibilitySpec
    policy_attestation: PolicyAttestation
    delegation_scope: DelegationScope


class SignedEdt(BaseModel):
    """EDT with Ed25519 signature envelope."""

    edt: EdtToken
    signature: str  # base64url-encoded Ed25519 signature
    kid: str
    alg: str = "Ed25519"


# ---------------------------------------------------------------------------
# Robot action / guard types
# ---------------------------------------------------------------------------


class RobotAction(BaseModel):
    """A physical robot action awaiting authorization."""

    description: str
    force_n: Optional[float] = None
    velocity_ms: Optional[float] = None
    zone: Optional[str] = None


class ClassificationResult(BaseModel):
    """Result of IrreversibilityClassifier."""

    action_class: IrreversibilityClass
    reason: str
    triggered_rule: str


class AuthorizationDecision(BaseModel):
    """Result of PreExecutionGuard.authorize()."""

    approved: bool
    classification: IrreversibilityClass
    reason: str
    edt_valid: bool
    blocked_at: Optional[str] = None  # signature|class_ceiling|class3_prohibited|excluded_zone|force_limit|velocity_limit
