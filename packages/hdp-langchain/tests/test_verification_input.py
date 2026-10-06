# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""Cross-language Section 3 input-validation vectors."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from hdp_langchain.verify import verify_chain


_VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "vectors"
    / "section3-validation.json"
)
_VECTOR = json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))
_TOKEN = _VECTOR["token"]
_PUBLIC_KEY = bytes.fromhex(_VECTOR["public_key_hex"])


def _assert_failed_step(result, step: int) -> None:
    assert result.valid is False
    assert result.violations[0].startswith(f"Step {step}:")


def test_correctly_signed_token_with_extra_top_level_member_fails_at_step_zero():
    token = deepcopy(_TOKEN)
    token["audit_note"] = "unsigned"

    _assert_failed_step(verify_chain(token, _PUBLIC_KEY), 0)


def test_incomplete_signature_object_fails_at_step_zero():
    token = deepcopy(_TOKEN)
    token["signature"] = {}

    _assert_failed_step(verify_chain(token, _PUBLIC_KEY), 0)


def test_unsupported_string_algorithm_fails_at_step_two():
    token = deepcopy(_TOKEN)
    token["signature"]["alg"] = "EdDSA"

    _assert_failed_step(verify_chain(token, _PUBLIC_KEY), 2)


def test_unmodified_shared_section_three_vector_verifies():
    result = verify_chain(deepcopy(_TOKEN), _PUBLIC_KEY)

    assert result.valid is True
    assert result.violations == []
