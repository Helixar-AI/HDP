"""Tests for IrreversibilityClassifier — driven by shared action-class-samples.json."""

import json
from pathlib import Path
from typing import Optional

import pytest

from hdp_physical.classifier import IrreversibilityClassifier
from hdp_physical.types import IrreversibilityClass, RobotAction

VECTORS = Path(__file__).parent / "vectors"
SAMPLES = json.loads((VECTORS / "action-class-samples.json").read_text())

classifier = IrreversibilityClassifier()


class TestVectors:
    @pytest.mark.parametrize(
        "sample",
        SAMPLES,
        ids=[s["label"] for s in SAMPLES],
    )
    def test_vector(self, sample: dict):
        action = RobotAction(
            description=sample["description"],
            force_n=sample.get("force_n"),
            velocity_ms=sample.get("velocity_ms"),
        )
        result = classifier.classify(action)
        assert result.action_class == IrreversibilityClass(sample["expected_class"]), (
            f"[{sample['label']}] expected class {sample['expected_class']}, "
            f"got {result.action_class} (rule={result.triggered_rule}, reason={result.reason!r})"
        )


class TestReasoning:
    def test_returns_non_empty_reason(self):
        result = classifier.classify(RobotAction(description="pick box"))
        assert len(result.reason) > 0
        assert len(result.triggered_rule) > 0

    def test_class_3_first_match(self):
        """Force at 95% threshold is caught by force_max before other rules."""
        result = classifier.classify(RobotAction(description="move box", force_n=42.75))
        assert result.action_class == IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL
        assert result.triggered_rule == "force_max"

    def test_sensor_query_class_0(self):
        result = classifier.classify(RobotAction(description="What is the current gripper state?"))
        assert result.action_class == IrreversibilityClass.REVERSIBLE

    def test_default_catch_all_class_1(self):
        result = classifier.classify(RobotAction(description="some unrecognised action"))
        assert result.action_class == IrreversibilityClass.REVERSIBLE_WITH_EFFORT
        assert result.triggered_rule == "default_manipulation"
