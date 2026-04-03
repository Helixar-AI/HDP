"""Fluent EdtBuilder for constructing Embodied Delegation Tokens."""

from __future__ import annotations

from typing import List, Optional

from hdp_physical.types import (
    ActionScope,
    DelegationScope,
    EdtToken,
    EmbodimentSpec,
    IrreversibilityClass,
    IrreversibilitySpec,
    PolicyAttestation,
)


class EdtBuilder:
    """Fluent builder for :class:`EdtToken`.

    Example::

        edt = (
            EdtBuilder()
            .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
            .set_action_scope(permitted_actions=["pick", "place"], excluded_zones=[], max_force_n=45, max_velocity_ms=0.5)
            .set_irreversibility(max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation=True, class3_prohibited=True)
            .set_policy_attestation(policy_hash="sha256-...", training_run_id="run-1", sim_validated=True)
            .set_delegation_scope(allow_fleet_delegation=False, max_delegation_depth=1, sub_agent_whitelist=[])
            .build()
        )
    """

    def __init__(self) -> None:
        self._embodiment: Optional[EmbodimentSpec] = None
        self._action_scope: Optional[ActionScope] = None
        self._irreversibility: Optional[IrreversibilitySpec] = None
        self._policy_attestation: Optional[PolicyAttestation] = None
        self._delegation_scope: Optional[DelegationScope] = None

    # ------------------------------------------------------------------
    # Fluent setters
    # ------------------------------------------------------------------

    def set_embodiment(
        self,
        *,
        agent_type: str,
        platform_id: str,
        workspace_scope: str,
    ) -> "EdtBuilder":
        self._embodiment = EmbodimentSpec(
            agent_type=agent_type,
            platform_id=platform_id,
            workspace_scope=workspace_scope,
        )
        return self

    def set_action_scope(
        self,
        *,
        permitted_actions: List[str],
        excluded_zones: List[str],
        max_force_n: float,
        max_velocity_ms: float,
    ) -> "EdtBuilder":
        self._action_scope = ActionScope(
            permitted_actions=permitted_actions,
            excluded_zones=excluded_zones,
            max_force_n=max_force_n,
            max_velocity_ms=max_velocity_ms,
        )
        return self

    def set_irreversibility(
        self,
        *,
        max_class: IrreversibilityClass,
        class2_requires_confirmation: bool = False,
        class3_prohibited: bool = True,
    ) -> "EdtBuilder":
        self._irreversibility = IrreversibilitySpec(
            max_class=max_class,
            class2_requires_confirmation=class2_requires_confirmation,
            class3_prohibited=class3_prohibited,
        )
        return self

    def set_policy_attestation(
        self,
        *,
        policy_hash: str,
        training_run_id: str,
        sim_validated: bool = False,
    ) -> "EdtBuilder":
        self._policy_attestation = PolicyAttestation(
            policy_hash=policy_hash,
            training_run_id=training_run_id,
            sim_validated=sim_validated,
        )
        return self

    def set_delegation_scope(
        self,
        *,
        allow_fleet_delegation: bool = False,
        max_delegation_depth: int = 1,
        sub_agent_whitelist: Optional[List[str]] = None,
    ) -> "EdtBuilder":
        self._delegation_scope = DelegationScope(
            allow_fleet_delegation=allow_fleet_delegation,
            max_delegation_depth=max_delegation_depth,
            sub_agent_whitelist=sub_agent_whitelist or [],
        )
        return self

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self) -> EdtToken:
        """Construct and return the :class:`EdtToken`.

        Raises :exc:`ValueError` if any required section is missing.
        """
        missing = [
            name
            for name, val in [
                ("embodiment", self._embodiment),
                ("action_scope", self._action_scope),
                ("irreversibility", self._irreversibility),
                ("policy_attestation", self._policy_attestation),
                ("delegation_scope", self._delegation_scope),
            ]
            if val is None
        ]
        if missing:
            raise ValueError(f"EdtBuilder missing required sections: {', '.join(missing)}")

        return EdtToken(
            embodiment=self._embodiment,  # type: ignore[arg-type]
            action_scope=self._action_scope,  # type: ignore[arg-type]
            irreversibility=self._irreversibility,  # type: ignore[arg-type]
            policy_attestation=self._policy_attestation,  # type: ignore[arg-type]
            delegation_scope=self._delegation_scope,  # type: ignore[arg-type]
        )
