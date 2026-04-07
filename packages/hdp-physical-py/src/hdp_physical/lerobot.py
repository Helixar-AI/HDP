"""LeRobot adapter — HDP-P guard integration for LeRobot action dicts.

LeRobot represents robot actions as numpy arrays or plain dicts.  This adapter
translates LeRobot-style action observations into :class:`RobotAction` objects
and runs them through the :class:`PreExecutionGuard` before they reach the
robot hardware.

The ``lerobot`` optional dependency is **not** imported at module level so this
file can be imported even when ``lerobot`` is not installed.  A
:class:`LeRobotGuardedPolicy` wrapper is provided for convenience; it wraps an
existing LeRobot policy and intercepts ``select_action`` calls.

Usage (with ``lerobot`` installed)::

    from hdp_physical.lerobot import LeRobotActionAdapter, LeRobotGuardedPolicy

    adapter = LeRobotActionAdapter(
        signed_edt=signed_edt,
        public_key=public_key,
        action_description_key="task",   # optional key in obs dict
    )

    async def safe_step(obs, action_dict):
        decision = await adapter.authorize(obs, action_dict)
        if decision.approved:
            env.step(action_dict)
        else:
            print(f"Blocked: {decision.reason}")
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hdp_physical.guard import PreExecutionGuard
from hdp_physical.types import AuthorizationDecision, RobotAction, SignedEdt

if TYPE_CHECKING:
    try:
        import numpy as np
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_scalar(value: Any) -> Optional[float]:
    """Extract a Python float from a numpy scalar, tensor, or plain number."""
    if value is None:
        return None
    try:
        # Works for numpy scalars and arrays of size 1
        return float(value)
    except (TypeError, ValueError):
        return None


def _action_dict_to_robot_action(
    action_dict: Dict[str, Any],
    description: str = "lerobot_action",
) -> RobotAction:
    """Map a LeRobot action dict to :class:`RobotAction`.

    Convention (keys are detected case-insensitively):
    - ``force`` / ``force_n`` → ``force_n``
    - ``velocity`` / ``velocity_ms`` → ``velocity_ms``
    - ``zone`` → ``zone``
    - ``task`` / ``description`` → ``description``
    """
    d = {k.lower(): v for k, v in action_dict.items()}

    force_n = _extract_scalar(d.get("force_n") or d.get("force"))
    velocity_ms = _extract_scalar(d.get("velocity_ms") or d.get("velocity"))
    zone = d.get("zone")
    desc = str(d.get("task") or d.get("description") or description)

    return RobotAction(
        description=desc,
        force_n=force_n,
        velocity_ms=velocity_ms,
        zone=zone,
    )


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class LeRobotActionAdapter:
    """Translates LeRobot action dicts into HDP-P authorization decisions.

    Parameters
    ----------
    signed_edt:
        The active Embodied Delegation Token.
    public_key:
        Ed25519 public key for EDT verification.
    default_description:
        Fallback description when no task/description key is in the action dict.
    """

    def __init__(
        self,
        signed_edt: SignedEdt,
        public_key: Ed25519PublicKey,
        default_description: str = "lerobot_action",
    ) -> None:
        self._signed_edt = signed_edt
        self._public_key = public_key
        self._default_description = default_description
        self._guard = PreExecutionGuard()

    async def authorize(
        self,
        action_dict: Dict[str, Any],
    ) -> AuthorizationDecision:
        """Authorize a LeRobot action dict.

        Parameters
        ----------
        action_dict:
            Raw action from a LeRobot policy (``select_action`` output or env step).

        Returns
        -------
        :class:`AuthorizationDecision`
        """
        robot_action = _action_dict_to_robot_action(action_dict, self._default_description)
        return await self._guard.authorize(robot_action, self._signed_edt, self._public_key)

    def authorize_sync(self, action_dict: Dict[str, Any]) -> AuthorizationDecision:
        """Synchronous wrapper around :meth:`authorize`.

        Runs the coroutine in a dedicated background thread so that it works
        whether or not an event loop is already running in the calling thread.
        """
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, self.authorize(action_dict))
            return future.result()


# ---------------------------------------------------------------------------
# Guarded policy wrapper (requires lerobot to be installed)
# ---------------------------------------------------------------------------


class LeRobotGuardedPolicy:
    """Wraps a LeRobot policy and guards every ``select_action`` call.

    Any action blocked by HDP-P raises :exc:`BlockedActionError` rather than
    reaching the robot hardware.  The caller can catch this and issue a safe
    fallback (e.g. stop motors).

    Requires ``lerobot`` to be installed (``pip install hdp-physical[lerobot]``).
    """

    def __init__(
        self,
        policy: Any,
        signed_edt: SignedEdt,
        public_key: Ed25519PublicKey,
    ) -> None:
        self._policy = policy
        self._adapter = LeRobotActionAdapter(
            signed_edt=signed_edt,
            public_key=public_key,
            default_description="lerobot_policy_action",
        )

    def select_action(self, observation: Any) -> Any:
        """Forward to wrapped policy; block if HDP-P rejects the output."""
        action = self._policy.select_action(observation)
        # Convert to dict if it's a tensor / numpy array
        if hasattr(action, "tolist"):
            action_dict = {"action": action.tolist()}
        elif hasattr(action, "items"):
            action_dict = dict(action)
        else:
            action_dict = {"action": action}

        decision = self._adapter.authorize_sync(action_dict)
        if not decision.approved:
            raise BlockedActionError(decision)
        return action


class BlockedActionError(Exception):
    """Raised when HDP-P blocks a LeRobot action."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        super().__init__(f"Action blocked at '{decision.blocked_at}': {decision.reason}")
        self.decision = decision
