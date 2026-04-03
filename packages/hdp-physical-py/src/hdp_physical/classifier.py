"""IrreversibilityClassifier — rule-based action classification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List

from hdp_physical.types import ClassificationResult, IrreversibilityClass, RobotAction

# Reference thresholds (matches the TypeScript SDK)
_MAX_FORCE_N: float = 45.0
_MAX_VELOCITY_MS: float = 0.5


@dataclass
class _Rule:
    name: str
    action_class: IrreversibilityClass
    match: Callable[[RobotAction], bool]
    reason: str


# ---------------------------------------------------------------------------
# Rule list — evaluated in order; first match wins.
# Class 3 is first so the most dangerous classification always wins.
# ---------------------------------------------------------------------------

_RULES: List[_Rule] = [
    # ── Class 3: harmful / irreversible ─────────────────────────────────────
    _Rule(
        name="force_max",
        action_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
        match=lambda a: a.force_n is not None and a.force_n >= _MAX_FORCE_N * 0.95,
        reason="Force at or above 95% of safe maximum — irreversible and harmful",
    ),
    _Rule(
        name="velocity_max",
        action_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
        match=lambda a: a.velocity_ms is not None and a.velocity_ms >= _MAX_VELOCITY_MS * 0.90,
        reason="Velocity at or above 90% of safe maximum — risk of uncontrolled movement",
    ),
    _Rule(
        name="dangerous_keywords",
        action_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
        match=lambda a: bool(
            re.search(
                r"crush|harm|dangerous|override|ignore.*safety|ignore.*limit|max.*speed|max.*velocity",
                a.description,
                re.IGNORECASE,
            )
        ),
        reason="Action description contains dangerous command keywords",
    ),
    _Rule(
        name="explicit_max_params",
        action_class=IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
        match=lambda a: bool(
            re.search(r"gripper_force=1\.0|velocity=2\.0", a.description, re.IGNORECASE)
        ),
        reason="Structured command requests maximum unsafe parameters",
    ),
    # ── Class 2: irreversible (normally) ────────────────────────────────────
    _Rule(
        name="force_high",
        action_class=IrreversibilityClass.IRREVERSIBLE_NORMALLY,
        match=lambda a: (
            a.force_n is not None
            and a.force_n >= _MAX_FORCE_N * 0.80
            and a.force_n < _MAX_FORCE_N * 0.95
        ),
        reason="Force exceeds 80% of safe maximum — action may be irreversible",
    ),
    _Rule(
        name="irreversible_keywords",
        action_class=IrreversibilityClass.IRREVERSIBLE_NORMALLY,
        match=lambda a: bool(
            re.search(
                r"press.fit|permanent|bond|cut|laser|weld|solder|seal",
                a.description,
                re.IGNORECASE,
            )
        ),
        reason="Action description indicates an irreversible physical operation",
    ),
    # ── Class 0: read-only / observation ─────────────────────────────────────
    _Rule(
        name="sensor_query",
        action_class=IrreversibilityClass.REVERSIBLE,
        match=lambda a: bool(
            re.search(
                r"sensor|query|read|observe|detect|measure|what is|status|state\?",
                a.description,
                re.IGNORECASE,
            )
        )
        and not bool(
            re.search(
                r"\bpick\b|\bplace\b|\bmove\b|\brotate\b|\bgrip\b",
                a.description,
                re.IGNORECASE,
            )
        ),
        reason="Read-only sensor query — no physical state change",
    ),
    # ── Class 1: default catch-all ────────────────────────────────────────────
    _Rule(
        name="default_manipulation",
        action_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
        match=lambda a: True,
        reason="Standard manipulation action within safe parameters",
    ),
]


class IrreversibilityClassifier:
    """Rule-based classifier that maps a :class:`RobotAction` to an :class:`IrreversibilityClass`.

    Rules are evaluated in order (Class 3 first).  The first matching rule wins.
    The final catch-all rule ensures every action gets a classification.
    """

    def classify(self, action: RobotAction) -> ClassificationResult:
        """Classify *action* and return a :class:`ClassificationResult`."""
        for rule in _RULES:
            if rule.match(action):
                return ClassificationResult(
                    action_class=rule.action_class,
                    reason=rule.reason,
                    triggered_rule=rule.name,
                )
        # Should never reach here (default_manipulation is a catch-all)
        return ClassificationResult(
            action_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
            reason="No rule matched",
            triggered_rule="fallback",
        )
