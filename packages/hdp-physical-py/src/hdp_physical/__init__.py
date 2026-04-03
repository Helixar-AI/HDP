"""hdp-physical — HDP-P Embodied Delegation Tokens for physical AI agents."""

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
from hdp_physical.signer import canonicalize_edt, sign_edt, verify_edt
from hdp_physical.builder import EdtBuilder
from hdp_physical.classifier import IrreversibilityClassifier
from hdp_physical.guard import PreExecutionGuard
from hdp_physical.chain import generate_mermaid_diagram

__all__ = [
    # Types
    "ActionScope",
    "AuthorizationDecision",
    "ClassificationResult",
    "DelegationScope",
    "EdtToken",
    "EmbodimentSpec",
    "IrreversibilityClass",
    "IrreversibilitySpec",
    "PolicyAttestation",
    "RobotAction",
    "SignedEdt",
    # Signer
    "canonicalize_edt",
    "sign_edt",
    "verify_edt",
    # Builder
    "EdtBuilder",
    # Classifier
    "IrreversibilityClassifier",
    # Guard
    "PreExecutionGuard",
    # Diagram
    "generate_mermaid_diagram",
]
