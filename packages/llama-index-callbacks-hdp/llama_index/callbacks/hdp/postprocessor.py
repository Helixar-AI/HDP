"""HdpNodePostprocessor — inline scope enforcement in the LlamaIndex RAG pipeline.

Runs after retrieval, before synthesis. Validates scope and records retrieval
as a hop in the HDP delegation chain.

Usage:
    from llama_index.callbacks.hdp import HdpNodePostprocessor

    postprocessor = HdpNodePostprocessor(
        signing_key=ed25519_private_key_bytes,  # same key used for HdpCallbackHandler
        strict=False,
    )

    query_engine = index.as_query_engine(
        node_postprocessors=[postprocessor]
    )

The postprocessor reads the active HDP token from the ContextVar. If no token
is present (HdpCallbackHandler or HdpInstrumentationHandler not configured),
it logs a warning and returns nodes unchanged.
"""

from __future__ import annotations

import logging
import time
from typing import Any, List, Optional

from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import NodeWithScore, QueryBundle

from ._crypto import sign_hop
from .callbacks import HDPScopeViolationError
from .session import get_token, set_token

logger = logging.getLogger(__name__)

_CLASSIFICATION_LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class HdpNodePostprocessor(BaseNodePostprocessor):
    """Records retrieval hops and optionally enforces data classification scope.

    Each call to _postprocess_nodes extends the active HDP token's delegation
    chain with a retrieval hop. This ensures every document retrieval is
    cryptographically recorded as part of the authorization provenance.

    Args:
        strict: If True, raise HDPScopeViolationError on classification
                violations. If False (default), log and continue.
        check_data_classification: If True (default), inspect each node's
                metadata for a 'classification' key and validate it against
                scope.data_classification.
    """

    strict: bool = False
    check_data_classification: bool = True

    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        strict: bool = False,
        check_data_classification: bool = True,
    ) -> None:
        super().__init__()
        self._signing_key = signing_key
        self.strict = strict
        self.check_data_classification = check_data_classification

    @classmethod
    def class_name(cls) -> str:
        return "HdpNodePostprocessor"

    def _postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        token = get_token()
        if token is None:
            logger.warning(
                "HDP: no active token in context — retrieval not recorded. "
                "Configure HdpCallbackHandler or HdpInstrumentationHandler before querying."
            )
            return nodes

        query_str = ""
        if query_bundle is not None:
            query_str = getattr(query_bundle, "query_str", "") or ""

        if self.check_data_classification:
            nodes = self._check_classification(nodes, token)

        self._extend_chain(token, nodes, query_str)
        return nodes

    def _check_classification(
        self,
        nodes: List[NodeWithScore],
        token: dict,
    ) -> List[NodeWithScore]:
        allowed_classification = token.get("scope", {}).get("data_classification", "internal")
        allowed_level = _CLASSIFICATION_LEVELS.get(allowed_classification, 1)
        violating = []

        for node in nodes:
            node_classification = node.node.metadata.get("classification", "internal") if node.node.metadata else "internal"
            node_level = _CLASSIFICATION_LEVELS.get(node_classification, 1)
            if node_level > allowed_level:
                violating.append((node, node_classification))

        if violating:
            violated_classes = [c for _, c in violating]
            msg = (
                f"HDP: retrieved nodes with classification {violated_classes} "
                f"exceed allowed level '{allowed_classification}'"
            )
            if self.strict:
                raise HDPScopeViolationError(
                    tool=f"retrieval[{violated_classes}]",
                    authorized_tools=[f"retrieval[<={allowed_classification}]"],
                )
            logger.warning(msg)
            self._record_classification_violation(token, violated_classes, allowed_classification)

        return nodes

    def _extend_chain(self, token: dict, nodes: List[NodeWithScore], query_str: str) -> None:
        current_chain: list = token.get("chain", [])
        next_seq = len(current_chain) + 1

        summary_parts = [f"retrieval: {len(nodes)} nodes"]
        if query_str:
            summary_parts.append(f"query: {query_str[:80]}")
        action_summary = ", ".join(summary_parts)

        unsigned_hop: dict = {
            "seq": next_seq,
            "agent_id": "llama-index-retriever",
            "agent_type": "tool-executor",
            "timestamp": int(time.time() * 1000),
            "action_summary": action_summary,
            "parent_hop": next_seq - 1,
        }

        try:
            if self._signing_key is None:
                logger.debug(
                    "HDP postprocessor: no signing key configured — recording unsigned retrieval hop"
                )
                token = {**token, "chain": [*current_chain, {**unsigned_hop, "hop_signature": ""}]}
                set_token(token)
                return

            cumulative = [*current_chain, unsigned_hop]
            hop_sig = sign_hop(cumulative, token["signature"]["value"], self._signing_key)
            signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
            token = {**token, "chain": [*current_chain, signed_hop]}
            set_token(token)
            logger.debug("HDP retrieval hop %d recorded", next_seq)
        except Exception as exc:
            logger.warning("HDP postprocessor chain extension failed (non-blocking): %s", exc)

    def _record_classification_violation(
        self,
        token: dict,
        violated_classes: list,
        allowed: str,
    ) -> None:
        scope = token.get("scope", {})
        extensions = scope.get("extensions", {})
        violations: list = extensions.get("classification_violations", [])
        violations.append({
            "violated_classifications": violated_classes,
            "allowed_classification": allowed,
            "timestamp": int(time.time() * 1000),
        })
        token["scope"] = {**scope, "extensions": {**extensions, "classification_violations": violations}}
        set_token(token)
