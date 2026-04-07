"""Gemma interceptor — HDP-P guard for Gemma-generated robot action strings.

Gemma (and other language-model) robot controllers emit actions as structured
text or JSON.  This module provides:

- :func:`parse_gemma_action` — parse a Gemma action string into a
  :class:`RobotAction`.
- :class:`GemmaActionInterceptor` — wrap a ``model.generate()`` pipeline and
  intercept every produced action through :class:`PreExecutionGuard` before it
  reaches the robot.

The ``transformers`` / ``torch`` optional dependencies are **not** imported at
module level.  A :class:`GemmaGuardedPipeline` convenience wrapper is provided
for full Gemma pipeline integration.

Usage (with ``hdp-physical[gemma]`` installed)::

    from hdp_physical.gemma import GemmaActionInterceptor

    interceptor = GemmaActionInterceptor(
        signed_edt=signed_edt,
        public_key=public_key,
    )

    action_text = model.generate(prompt)
    decision = await interceptor.authorize(action_text)
    if decision.approved:
        execute(action_text)
    else:
        print(f"Blocked: {decision.reason}")
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hdp_physical.guard import PreExecutionGuard
from hdp_physical.types import AuthorizationDecision, RobotAction, SignedEdt


# ---------------------------------------------------------------------------
# Gemma action text parser
# ---------------------------------------------------------------------------

# Common structured action patterns emitted by robot LLMs:
#   action: pick_place(force=10, velocity=0.3)
#   {"action": "pick box", "force_n": 10, "velocity_ms": 0.3}
#   ROBOT_CMD: move_to zone=B force=5

_JSON_RE = re.compile(r"\{[^}]+\}", re.DOTALL)
_PARAM_RE = re.compile(r"(\w+)\s*[=:]\s*([\d.]+)")
_ZONE_RE = re.compile(r"zone[_\s]?[=:]\s*(\S+)", re.IGNORECASE)


def parse_gemma_action(text: str) -> RobotAction:
    """Parse a Gemma-emitted action string into a :class:`RobotAction`.

    Attempts JSON parsing first, then falls back to key=value parameter
    extraction.  The raw *text* is always used as the ``description`` so the
    classifier can inspect it for dangerous keywords.

    Parameters
    ----------
    text:
        Raw action text produced by the Gemma model.

    Returns
    -------
    :class:`RobotAction`
    """
    description = text.strip()
    force_n: Optional[float] = None
    velocity_ms: Optional[float] = None
    zone: Optional[str] = None

    # Try JSON extraction
    json_match = _JSON_RE.search(text)
    if json_match:
        try:
            data = json.loads(json_match.group())
            if isinstance(data, dict):
                desc_raw = data.get("action") or data.get("description") or data.get("task")
                if desc_raw:
                    description = str(desc_raw)
                force_n = _to_float(data.get("force_n") or data.get("force"))
                velocity_ms = _to_float(data.get("velocity_ms") or data.get("velocity"))
                zone = data.get("zone")
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: key=value parameter scan
    if force_n is None and velocity_ms is None:
        for key, val in _PARAM_RE.findall(text):
            k = key.lower()
            if k in ("force", "force_n", "gripper_force"):
                force_n = _to_float(val)
            elif k in ("velocity", "velocity_ms", "vel"):
                velocity_ms = _to_float(val)

    if zone is None:
        zm = _ZONE_RE.search(text)
        if zm:
            zone = zm.group(1).strip("\"'")

    return RobotAction(
        description=description,
        force_n=force_n,
        velocity_ms=velocity_ms,
        zone=zone,
    )


def _to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Interceptor
# ---------------------------------------------------------------------------


class GemmaActionInterceptor:
    """Intercepts Gemma-produced action strings and runs them through HDP-P.

    Parameters
    ----------
    signed_edt:
        The active Embodied Delegation Token.
    public_key:
        Ed25519 public key for EDT verification.
    """

    def __init__(self, signed_edt: SignedEdt, public_key: Ed25519PublicKey) -> None:
        self._signed_edt = signed_edt
        self._public_key = public_key
        self._guard = PreExecutionGuard()

    async def authorize(self, action_text: str) -> AuthorizationDecision:
        """Parse *action_text* and authorize it through HDP-P.

        Parameters
        ----------
        action_text:
            Raw text produced by the Gemma model.

        Returns
        -------
        :class:`AuthorizationDecision`
        """
        action = parse_gemma_action(action_text)
        return await self._guard.authorize(action, self._signed_edt, self._public_key)


# ---------------------------------------------------------------------------
# Guarded pipeline wrapper (requires transformers + torch)
# ---------------------------------------------------------------------------


class GemmaGuardedPipeline:
    """Wraps a HuggingFace ``pipeline`` / ``model.generate()`` and guards outputs.

    Every generated action string is intercepted by :class:`GemmaActionInterceptor`
    before being returned.  Blocked actions raise :exc:`BlockedGemmaActionError`.

    Requires ``hdp-physical[gemma]`` (``transformers>=4.50.0``, ``torch>=2.3.0``).

    Parameters
    ----------
    pipeline:
        A callable that accepts a prompt string and returns generated text
        (e.g. a HuggingFace ``pipeline("text-generation", ...)``,
        or ``model.generate`` with a tokenizer wrapper).
    signed_edt:
        The active Embodied Delegation Token.
    public_key:
        Ed25519 public key for EDT verification.
    """

    def __init__(
        self,
        pipeline: Any,
        signed_edt: SignedEdt,
        public_key: Ed25519PublicKey,
    ) -> None:
        self._pipeline = pipeline
        self._interceptor = GemmaActionInterceptor(signed_edt=signed_edt, public_key=public_key)

    async def generate(self, prompt: str) -> str:
        """Generate an action with Gemma and authorize it through HDP-P.

        Parameters
        ----------
        prompt:
            Input prompt for the model.

        Returns
        -------
        str
            The generated action text (only returned if HDP-P approved it).

        Raises
        ------
        :exc:`BlockedGemmaActionError`
            If HDP-P blocks the generated action.
        """
        # Support plain callables and HF pipeline objects
        raw = self._pipeline(prompt)
        if isinstance(raw, list):
            action_text = raw[0].get("generated_text", "") if isinstance(raw[0], dict) else str(raw[0])
        else:
            action_text = str(raw)

        decision = await self._interceptor.authorize(action_text)
        if not decision.approved:
            raise BlockedGemmaActionError(action_text, decision)
        return action_text


class BlockedGemmaActionError(Exception):
    """Raised when HDP-P blocks a Gemma-generated action."""

    def __init__(self, action_text: str, decision: AuthorizationDecision) -> None:
        super().__init__(
            f"Gemma action blocked at '{decision.blocked_at}': {decision.reason}\n"
            f"Action: {action_text!r}"
        )
        self.action_text = action_text
        self.decision = decision
