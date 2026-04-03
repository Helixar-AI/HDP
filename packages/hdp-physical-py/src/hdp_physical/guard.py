"""PreExecutionGuard — six-step authorization gate for physical robot actions."""

from __future__ import annotations

from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hdp_physical.classifier import IrreversibilityClassifier
from hdp_physical.signer import verify_edt
from hdp_physical.types import (
    AuthorizationDecision,
    IrreversibilityClass,
    RobotAction,
    SignedEdt,
)

_classifier = IrreversibilityClassifier()


class PreExecutionGuard:
    """Six-step authorization gate that must approve every robot action.

    Authorization steps (in order):
    1. Signature verification
    2. Class 3 prohibition check
    3. Irreversibility class ceiling
    4. Excluded zone check
    5. Force limit check
    6. Velocity limit check
    """

    async def authorize(
        self,
        action: Union[RobotAction, dict],
        signed_edt: SignedEdt,
        public_key: Ed25519PublicKey,
    ) -> AuthorizationDecision:
        """Authorize *action* against *signed_edt*.

        Parameters
        ----------
        action:
            A :class:`RobotAction` or a plain dict with the same fields.
        signed_edt:
            The signed Embodied Delegation Token to validate against.
        public_key:
            Ed25519 public key corresponding to the signing key.

        Returns
        -------
        :class:`AuthorizationDecision`
        """
        if isinstance(action, dict):
            action = RobotAction.model_validate(action)

        edt = signed_edt.edt

        # ── Step 1: Signature verification ───────────────────────────────────
        sig_valid = await verify_edt(signed_edt, public_key)
        if not sig_valid:
            classification = _classifier.classify(action)
            return AuthorizationDecision(
                approved=False,
                classification=classification.action_class,
                reason="EDT signature is invalid — command rejected",
                edt_valid=False,
                blocked_at="signature",
            )

        # Classify the action (used in all subsequent checks)
        classification = _classifier.classify(action)
        action_class = classification.action_class

        # ── Step 2: Class 3 prohibition ───────────────────────────────────────
        if edt.irreversibility.class3_prohibited and action_class == IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL:
            return AuthorizationDecision(
                approved=False,
                classification=action_class,
                reason=f"Class 3 (harmful/irreversible) actions are prohibited by this EDT",
                edt_valid=True,
                blocked_at="class3_prohibited",
            )

        # ── Step 3: Irreversibility class ceiling ─────────────────────────────
        if action_class > edt.irreversibility.max_class:
            return AuthorizationDecision(
                approved=False,
                classification=action_class,
                reason=(
                    f"Action class {action_class} exceeds EDT ceiling "
                    f"{edt.irreversibility.max_class}"
                ),
                edt_valid=True,
                blocked_at="class_ceiling",
            )

        # ── Step 4: Excluded zone check ───────────────────────────────────────
        if action.zone and action.zone in edt.action_scope.excluded_zones:
            return AuthorizationDecision(
                approved=False,
                classification=action_class,
                reason=f"Zone '{action.zone}' is excluded by this EDT",
                edt_valid=True,
                blocked_at="excluded_zone",
            )

        # ── Step 5: Force limit check ─────────────────────────────────────────
        if action.force_n is not None and action.force_n > edt.action_scope.max_force_n:
            return AuthorizationDecision(
                approved=False,
                classification=action_class,
                reason=(
                    f"Requested force {action.force_n} N exceeds EDT limit "
                    f"{edt.action_scope.max_force_n} N"
                ),
                edt_valid=True,
                blocked_at="force_limit",
            )

        # ── Step 6: Velocity limit check ─────────────────────────────────────
        if action.velocity_ms is not None and action.velocity_ms > edt.action_scope.max_velocity_ms:
            return AuthorizationDecision(
                approved=False,
                classification=action_class,
                reason=(
                    f"Requested velocity {action.velocity_ms} m/s exceeds EDT limit "
                    f"{edt.action_scope.max_velocity_ms} m/s"
                ),
                edt_valid=True,
                blocked_at="velocity_limit",
            )

        # ── All checks passed ─────────────────────────────────────────────────
        return AuthorizationDecision(
            approved=True,
            classification=action_class,
            reason="All authorization checks passed",
            edt_valid=True,
            blocked_at=None,
        )
