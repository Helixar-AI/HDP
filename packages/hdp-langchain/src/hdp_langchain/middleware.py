"""HdpMiddleware — non-blocking HDP audit trail for LangChain agents.

Design considerations implemented:
  #1 Scope observation: on_tool_start() records out-of-scope tool attempts.
  #2 Recording depth: chain extension stops at max_hops.
  #3 Token size / performance: non-blocking throughout; Ed25519 = 64 bytes/hop.
  #4 Verification: see hdp_langchain.verify.verify_chain().
  #5 Callback integration: get_callback_handler() returns an HdpCallbackHandler
     that attaches to any chain or agent via LangChain's RunnableConfig.

Usage:
    from hdp_langchain import HdpMiddleware, HdpPrincipal, ScopePolicy, verify_chain

    middleware = HdpMiddleware(
        signing_key=ed25519_private_key_bytes,
        session_id="session-abc123",
        principal=HdpPrincipal(id="user@example.com", id_type="email"),
        scope=ScopePolicy(
            intent="Research agents via LangChain",
            authorized_tools=["web_search", "file_reader"],
            max_hops=10,
        ),
    )

    handler = middleware.get_callback_handler()

    # Attach to any chain, agent, or tool via RunnableConfig
    result = chain.invoke({"input": "..."}, config={"callbacks": [handler]})

    # After the run, inspect the delegation chain
    print(middleware.export_token_json())
"""

from __future__ import annotations

from copy import deepcopy
import json
import logging
import time
import uuid
from typing import Any, Optional, Union
from uuid import UUID

from langchain_core.callbacks.base import BaseCallbackHandler

from ._crypto import sign_hop, sign_root
from ._types import HdpPrincipal, DataClassification
from .verify import _validate_token_input

logger = logging.getLogger(__name__)


class HDPScopeViolationError(Exception):
    """Deprecated. Kept importable for compatibility and never raised."""

    def __init__(self, tool: str, authorized_tools: list[str]) -> None:
        self.tool = tool
        self.authorized_tools = authorized_tools
        super().__init__(
            f"Tool '{tool}' is not in the authorized scope {authorized_tools}"
        )


class ScopePolicy:
    """Human-readable policy that becomes the HDP scope field."""

    def __init__(
        self,
        intent: str,
        data_classification: DataClassification = "internal",
        network_egress: bool = True,
        persistence: bool = False,
        authorized_tools: Optional[list[str]] = None,
        authorized_resources: Optional[list[str]] = None,
        max_hops: Optional[int] = None,
    ) -> None:
        self.intent = intent
        self.data_classification = data_classification
        self.network_egress = network_egress
        self.persistence = persistence
        self.authorized_tools = authorized_tools
        self.authorized_resources = authorized_resources
        self.max_hops = max_hops

    def to_dict(self) -> dict:
        d: dict = {
            "intent": self.intent,
            "data_classification": self.data_classification,
            "network_egress": self.network_egress,
            "persistence": self.persistence,
        }
        if self.authorized_tools is not None:
            d["authorized_tools"] = self.authorized_tools
        if self.authorized_resources is not None:
            d["authorized_resources"] = self.authorized_resources
        if self.max_hops is not None:
            d["max_hops"] = self.max_hops
        return d


class HdpMiddleware:
    """Record HDP provenance for LangChain without gating agent actions.

    Integrates with LangChain's callback system to build a tamper-evident
    delegation chain for any chain, agent, or tool invocation.

    HDP tokens are records and cannot gate actions. ``strict=True`` is retained
    for compatibility and raises ValueError during construction.

    Usage::

        handler = middleware.get_callback_handler()
        chain.invoke(input, config={"callbacks": [handler]})
    """

    def __init__(
        self,
        signing_key: bytes,
        session_id: str,
        principal: HdpPrincipal,
        scope: ScopePolicy,
        key_id: str = "default",
        expires_in_ms: int = 24 * 60 * 60 * 1000,
        strict: bool = False,
    ) -> None:
        if strict:
            raise ValueError("HDP tokens are records and cannot gate actions")
        self._signing_key = signing_key
        self._session_id = session_id
        self._principal = principal
        self._scope = scope
        self._key_id = key_id
        self._expires_in_ms = expires_in_ms
        self._token: Optional[dict] = None
        self._hop_seq = 0

    # ------------------------------------------------------------------
    # Root token issuance
    # ------------------------------------------------------------------

    def before_kickoff(self) -> None:
        """Issue the HDP root token. Called automatically by HdpCallbackHandler."""
        now = int(time.time() * 1000)
        unsigned: dict = {
            "hdp": "0.1",
            "header": {
                "token_id": str(uuid.uuid4()),
                "issued_at": now,
                "expires_at": now + self._expires_in_ms,
                "session_id": self._session_id,
                "version": "0.1",
            },
            "principal": self._build_principal_dict(),
            "scope": self._scope.to_dict(),
            "chain": [],
        }
        candidate = {**unsigned, "signature": {"alg": "Ed25519", "kid": self._key_id, "value": "A" * 86}}
        input_error = _validate_token_input(candidate)
        if input_error is not None:
            raise ValueError(input_error)
        try:
            signature = sign_root(unsigned, self._signing_key, self._key_id)
            self._token = {**unsigned, "signature": signature}
            logger.debug("HDP root token issued: %s", self._token["header"]["token_id"])
        except Exception:
            logger.warning("HDP root record signing failed; action continues")

    # ------------------------------------------------------------------
    # Callback handler factory
    # ------------------------------------------------------------------

    def get_callback_handler(self) -> "HdpCallbackHandler":
        """Return an HdpCallbackHandler bound to this middleware.

        Pass the handler to any LangChain chain or agent::

            result = chain.invoke(input, config={"callbacks": [middleware.get_callback_handler()]})
        """
        return HdpCallbackHandler(self)

    # ------------------------------------------------------------------
    # Inspection / export
    # ------------------------------------------------------------------

    def export_token(self) -> Optional[dict]:
        """Return a defensive copy of the current token, if one was issued."""
        return deepcopy(self._token)

    def export_token_json(self, indent: int = 2) -> Optional[str]:
        """Return the token as a JSON string, or None if no token has been issued."""
        if self._token is None:
            return None
        return json.dumps(self._token, indent=indent)

    # ------------------------------------------------------------------
    # Internal: chain extension
    # ------------------------------------------------------------------

    def _extend_chain(self, agent_id: str, action_summary: str, agent_type: str = "sub-agent") -> None:
        """Append a signed hop to the delegation chain.

        A full chain is not extended; the LangChain action continues.
        """
        try:
            if self._token is None:
                return

            max_hops = self._scope.max_hops
            if max_hops is not None and self._hop_seq >= max_hops:
                logger.warning("HDP max_hops (%d) reached; hop was not recorded", max_hops)
                return

            input_error = _validate_token_input(self._token)
            if input_error is not None:
                raise ValueError(input_error)

            next_seq = self._hop_seq + 1
            unsigned_hop: dict = {
                "seq": next_seq,
                "agent_id": agent_id,
                "agent_type": agent_type,
                "timestamp": int(time.time() * 1000),
                "action_summary": action_summary,
                "parent_hop": next_seq - 1,
            }

            current_chain: list = self._token.get("chain", [])
            candidate = {
                **self._token,
                "chain": [*current_chain, {**unsigned_hop, "hop_signature": "A" * 86}],
            }
            input_error = _validate_token_input(candidate)
            if input_error is not None:
                raise ValueError(input_error)

            cumulative = [*current_chain, unsigned_hop]
            hop_sig = sign_hop(cumulative, self._token["signature"]["value"], self._signing_key)
            signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
            self._token = {**self._token, "chain": [*current_chain, signed_hop]}
            self._hop_seq = next_seq
            logger.debug("HDP hop %d recorded for agent '%s'", next_seq, agent_id)
        except Exception:
            logger.warning("HDP audit record append failed; action continues")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_principal_dict(self) -> dict:
        d: dict = {"id": self._principal.id, "id_type": self._principal.id_type}
        if self._principal.display_name is not None:
            d["display_name"] = self._principal.display_name
        if self._principal.metadata is not None:
            d["metadata"] = self._principal.metadata
        return d

    def _record_scope_violation(self, tool: str) -> None:
        """Append a signed hop describing an out-of-scope attempt."""
        self._extend_chain(
            agent_id=tool,
            action_summary=f"attempted out-of-scope tool call: {tool}",
            agent_type="tool-executor",
        )


class HdpCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that records delegation hops in an HDP chain.

    Attach to any chain, agent, or tool via LangChain's RunnableConfig::

        handler = middleware.get_callback_handler()
        chain.invoke(input, config={"callbacks": [handler]})

    Integration points:
      - ``on_chain_start``: Issues the HDP root token on the outermost chain start.
      - ``on_tool_start``: Records a delegation hop per tool call.
      - ``on_chain_end``: Logs completion when the outermost chain finishes.
    """

    def __init__(self, middleware: HdpMiddleware) -> None:
        super().__init__()
        self._middleware = middleware
        self._chain_depth = 0

    # ------------------------------------------------------------------
    # Chain lifecycle
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if self._chain_depth == 0 and self._middleware._token is None:
            self._middleware.before_kickoff()
        self._chain_depth += 1

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        self._chain_depth = max(0, self._chain_depth - 1)
        if self._chain_depth == 0:
            logger.debug("HDP: outermost chain completed")

    # ------------------------------------------------------------------
    # Tool invocation (primary hop recording point)
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        try:
            tool_name = _extract_tool_name(serialized)
            authorized = self._middleware._scope.authorized_tools
            if authorized is not None and tool_name not in authorized:
                logger.warning(
                    "HDP scope violation: tool '%s' not in authorized_tools %s",
                    tool_name,
                    authorized,
                )
                self._middleware._record_scope_violation(tool_name)

            summary = f"Tool '{tool_name}' invoked: {input_str[:200]}"
            self._middleware._extend_chain(
                agent_id=tool_name,
                action_summary=summary,
                agent_type="tool-executor",
            )
        except Exception:
            logger.warning("HDP audit record append failed; action continues")

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        pass  # Hop is recorded on start; end is informational only.

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        logger.warning("HDP: tool error (non-blocking): %s", error)

    # ------------------------------------------------------------------
    # Chain errors (non-blocking)
    # ------------------------------------------------------------------

    def on_chain_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        self._chain_depth = max(0, self._chain_depth - 1)
        logger.warning("HDP: chain error (non-blocking): %s", error)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_tool_name(serialized: dict) -> str:
    """Extract a tool name from LangChain's serialized component dict.

    LangChain's serialized dict structure varies across versions:
      - serialized["name"] — most common, set by Tool.name
      - serialized["id"][-1] — fallback, contains the class name
    """
    name = serialized.get("name") if isinstance(serialized, dict) else None
    if name:
        return str(name)
    id_list = serialized.get("id", []) if isinstance(serialized, dict) else []
    if id_list:
        return str(id_list[-1])
    return "unknown_tool"
