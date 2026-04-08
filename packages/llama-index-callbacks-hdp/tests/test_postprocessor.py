"""Tests for HdpNodePostprocessor — retrieval hop recording and scope enforcement."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from llama_index.core.schema import NodeWithScore, TextNode
from llama_index.callbacks.hdp import (
    HDPScopeViolationError,
    HdpNodePostprocessor,
    HdpPrincipal,
    ScopePolicy,
    verify_chain,
)
from llama_index.callbacks.hdp.callbacks import HdpCallbackHandler
from llama_index.callbacks.hdp.session import clear_token, get_token, set_token


def _generate_key():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key()


def _issue_token(signing_key: bytes, scope: ScopePolicy | None = None) -> dict:
    """Issue a minimal root token and store it in the ContextVar."""
    import time, uuid
    from llama_index.callbacks.hdp._crypto import sign_root
    now = int(time.time() * 1000)
    scope = scope or ScopePolicy(intent="test")
    unsigned = {
        "hdp": "0.1",
        "header": {
            "token_id": str(uuid.uuid4()),
            "issued_at": now,
            "expires_at": now + 86400000,
            "session_id": "test-session",
            "version": "0.1",
        },
        "principal": {"id": "user@test.com", "id_type": "email"},
        "scope": scope.to_dict(),
        "chain": [],
    }
    sig = sign_root(unsigned, signing_key, "default")
    token = {**unsigned, "signature": sig}
    set_token(token)
    return token


def _make_nodes(*classifications: str) -> list[NodeWithScore]:
    nodes = []
    for cls in classifications:
        metadata = {"classification": cls} if cls else {}
        nodes.append(NodeWithScore(node=TextNode(text="content", metadata=metadata), score=1.0))
    return nodes


class TestRetrievelHopRecording:
    def setup_method(self):
        clear_token()

    def test_records_retrieval_hop_with_signing_key(self):
        key, pub = _generate_key()
        _issue_token(key)
        pp = HdpNodePostprocessor(signing_key=key)
        nodes = _make_nodes("public", "public")
        result = pp._postprocess_nodes(nodes)
        assert result == nodes
        chain = get_token()["chain"]
        assert len(chain) == 1
        assert "retrieval: 2 nodes" in chain[0]["action_summary"]

    def test_retrieval_hop_is_signed(self):
        key, pub = _generate_key()
        _issue_token(key)
        pp = HdpNodePostprocessor(signing_key=key)
        pp._postprocess_nodes(_make_nodes("public"))
        result = verify_chain(get_token(), pub.public_bytes_raw())
        assert result.valid

    def test_without_signing_key_records_unsigned_hop(self):
        key, _ = _generate_key()
        _issue_token(key)
        pp = HdpNodePostprocessor()  # no signing_key
        pp._postprocess_nodes(_make_nodes("public"))
        chain = get_token()["chain"]
        assert len(chain) == 1
        assert chain[0]["hop_signature"] == ""

    def test_no_active_token_returns_nodes_unchanged(self):
        pp = HdpNodePostprocessor()
        nodes = _make_nodes("public", "internal")
        result = pp._postprocess_nodes(nodes)
        assert result == nodes

    def test_query_str_included_in_hop_summary(self):
        from llama_index.core.schema import QueryBundle
        key, _ = _generate_key()
        _issue_token(key)
        pp = HdpNodePostprocessor(signing_key=key)
        qb = QueryBundle(query_str="what is AI?")
        pp._postprocess_nodes(_make_nodes("public"), query_bundle=qb)
        summary = get_token()["chain"][0]["action_summary"]
        assert "what is AI?" in summary


class TestDataClassificationEnforcement:
    def setup_method(self):
        clear_token()

    def test_nodes_within_classification_pass(self):
        key, _ = _generate_key()
        _issue_token(key, ScopePolicy(intent="x", data_classification="confidential"))
        pp = HdpNodePostprocessor(signing_key=key, check_data_classification=True)
        nodes = _make_nodes("public", "internal", "confidential")
        result = pp._postprocess_nodes(nodes)
        assert len(result) == 3
        violations = get_token()["scope"].get("extensions", {}).get("classification_violations", [])
        assert violations == []

    def test_nodes_above_classification_logged_in_observe_mode(self):
        key, _ = _generate_key()
        _issue_token(key, ScopePolicy(intent="x", data_classification="internal"))
        pp = HdpNodePostprocessor(signing_key=key, check_data_classification=True, strict=False)
        nodes = _make_nodes("public", "restricted")  # restricted > internal
        result = pp._postprocess_nodes(nodes)
        assert len(result) == 2  # observe mode: nodes still returned
        violations = get_token()["scope"]["extensions"]["classification_violations"]
        assert len(violations) == 1
        assert "restricted" in violations[0]["violated_classifications"]

    def test_strict_mode_raises_on_classification_violation(self):
        key, _ = _generate_key()
        _issue_token(key, ScopePolicy(intent="x", data_classification="internal"))
        pp = HdpNodePostprocessor(signing_key=key, check_data_classification=True, strict=True)
        with pytest.raises(HDPScopeViolationError):
            pp._postprocess_nodes(_make_nodes("restricted"))

    def test_check_data_classification_false_skips_check(self):
        key, _ = _generate_key()
        _issue_token(key, ScopePolicy(intent="x", data_classification="public"))
        pp = HdpNodePostprocessor(signing_key=key, check_data_classification=False)
        # restricted nodes should pass through without any violation
        nodes = _make_nodes("restricted")
        result = pp._postprocess_nodes(nodes)
        assert result == nodes
        assert "classification_violations" not in get_token()["scope"].get("extensions", {})

    def test_nodes_without_classification_default_to_internal(self):
        key, _ = _generate_key()
        _issue_token(key, ScopePolicy(intent="x", data_classification="internal"))
        pp = HdpNodePostprocessor(signing_key=key, check_data_classification=True)
        # Node with no classification metadata should be treated as "internal"
        node = NodeWithScore(node=TextNode(text="no metadata"), score=1.0)
        result = pp._postprocess_nodes([node])
        assert len(result) == 1
        assert "classification_violations" not in get_token()["scope"].get("extensions", {})
