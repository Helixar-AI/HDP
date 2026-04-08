"""HdpCallbackHandler — legacy CallbackManager integration for LlamaIndex.

For users on LlamaIndex <0.10.20 or who prefer configuring via Settings.callback_manager.

Usage:
    from llama_index.callbacks.hdp import HdpCallbackHandler, HdpPrincipal, ScopePolicy
    from llama_index.core import Settings
    from llama_index.core.callbacks import CallbackManager

    handler = HdpCallbackHandler(
        signing_key=ed25519_private_key_bytes,
        principal=HdpPrincipal(id="alice@corp.com", id_type="email"),
        scope=ScopePolicy(
            intent="Research pipeline",
            authorized_tools=["web_search", "retriever"],
        ),
    )
    Settings.callback_manager = CallbackManager([handler])

    # Run your query engine / agent as normal. Retrieve the token after:
    token = handler.export_token()
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable, Optional

from llama_index.core.callbacks import CBEventType, EventPayload
from llama_index.core.callbacks.base_handler import BaseCallbackHandler

from ._crypto import sign_hop, sign_root
from ._types import DataClassification, HdpPrincipal
from .session import get_token, set_token

logger = logging.getLogger(__name__)


class HDPScopeViolationError(Exception):
    """Raised when an agent attempts to use a tool outside the authorized scope."""

    def __init__(self, tool: str, authorized_tools: list[str]) -> None:
        self.tool = tool
        self.authorized_tools = authorized_tools
        super().__init__(f"Tool '{tool}' is not in the authorized scope {authorized_tools}")


class ScopePolicy:
    """Human-readable policy that maps to the HDP scope field."""

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


class HdpCallbackHandler(BaseCallbackHandler):
    """HDP audit trail via LlamaIndex's legacy CallbackManager.

    Hooks into start_trace / end_trace for token lifecycle, and
    on_event_start / on_event_end for tool calls and LLM events.

    All HDP operations are non-blocking by default: failures are logged
    and execution continues. Set strict=True to raise HDPScopeViolationError
    on scope violations.
    """

    def __init__(
        self,
        signing_key: bytes,
        principal: HdpPrincipal,
        scope: ScopePolicy,
        key_id: str = "default",
        expires_in_ms: int = 24 * 60 * 60 * 1000,
        strict: bool = False,
        on_token_ready: Optional[Callable[[dict], None]] = None,
    ) -> None:
        super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
        self._signing_key = signing_key
        self._principal = principal
        self._scope = scope
        self._key_id = key_id
        self._expires_in_ms = expires_in_ms
        self._strict = strict
        self._on_token_ready = on_token_ready
        self._hop_seq = 0

    # ------------------------------------------------------------------
    # BaseCallbackHandler abstract methods
    # ------------------------------------------------------------------

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        """Issue the HDP root token. Called at the start of each query."""
        try:
            session_id = trace_id or str(uuid.uuid4())
            now = int(time.time() * 1000)
            unsigned: dict = {
                "hdp": "0.1",
                "header": {
                    "token_id": str(uuid.uuid4()),
                    "issued_at": now,
                    "expires_at": now + self._expires_in_ms,
                    "session_id": session_id,
                    "version": "0.1",
                },
                "principal": self._build_principal_dict(),
                "scope": self._scope.to_dict(),
                "chain": [],
            }
            signature = sign_root(unsigned, self._signing_key, self._key_id)
            token = {**unsigned, "signature": signature}
            set_token(token)
            self._hop_seq = 0
            logger.debug("HDP root token issued: %s", token["header"]["token_id"])
        except Exception as exc:
            logger.warning("HDP start_trace failed (non-blocking): %s", exc)

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[dict[str, list[str]]] = None,
    ) -> None:
        """Finalize the HDP token and invoke on_token_ready if configured."""
        try:
            token = get_token()
            if token is not None and self._on_token_ready is not None:
                self._on_token_ready(token)
        except Exception as exc:
            logger.warning("HDP end_trace failed (non-blocking): %s", exc)

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        try:
            if event_type == CBEventType.FUNCTION_CALL:
                self._handle_tool_start(payload or {})
            elif event_type == CBEventType.LLM:
                self._handle_llm_start(payload or {})
            elif event_type == CBEventType.QUERY:
                self._handle_query_start(payload or {})
            elif event_type == CBEventType.EXCEPTION:
                self._handle_exception(payload or {})
        except HDPScopeViolationError:
            raise
        except Exception as exc:
            logger.warning("HDP on_event_start failed (non-blocking): %s", exc)
        return event_id

    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        try:
            if event_type == CBEventType.FUNCTION_CALL:
                self._handle_tool_end(payload or {})
        except Exception as exc:
            logger.warning("HDP on_event_end failed (non-blocking): %s", exc)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def export_token(self) -> Optional[dict]:
        """Return the current token dict from the ContextVar."""
        return get_token()

    # ------------------------------------------------------------------
    # Internal handlers
    # ------------------------------------------------------------------

    def _handle_tool_start(self, payload: dict) -> None:
        tool = payload.get(EventPayload.TOOL)
        tool_name: str = getattr(tool, "name", str(tool)) if tool is not None else "unknown-tool"

        authorized = self._scope.authorized_tools
        if authorized is not None and tool_name not in authorized:
            if self._strict:
                raise HDPScopeViolationError(tool_name, authorized)
            logger.warning(
                "HDP scope violation: tool '%s' not in authorized_tools %s",
                tool_name,
                authorized,
            )
            self._record_scope_violation(tool_name)

        self._extend_chain(action_summary=f"tool_call: {tool_name}")

    def _handle_tool_end(self, payload: dict) -> None:
        output = payload.get(EventPayload.FUNCTION_OUTPUT)
        if output is not None:
            token = get_token()
            if token and token.get("chain"):
                last_hop = token["chain"][-1]
                last_hop["metadata"] = {
                    **last_hop.get("metadata", {}),
                    "tool_output_preview": str(output)[:200],
                }

    def _handle_llm_start(self, payload: dict) -> None:
        model_name = payload.get(EventPayload.MODEL_NAME) or payload.get("model_name", "")
        if model_name:
            token = get_token()
            if token and token.get("chain"):
                last_hop = token["chain"][-1]
                last_hop["metadata"] = {
                    **last_hop.get("metadata", {}),
                    "llm_model": model_name,
                }

    def _handle_query_start(self, payload: dict) -> None:
        query_str = payload.get(EventPayload.QUERY_STR, "")
        if query_str:
            token = get_token()
            if token:
                scope = token.get("scope", {})
                token["scope"] = {
                    **scope,
                    "extensions": {
                        **scope.get("extensions", {}),
                        "query_intent": str(query_str)[:500],
                    },
                }

    def _handle_exception(self, payload: dict) -> None:
        exc = payload.get(EventPayload.EXCEPTION)
        if exc is not None:
            self._record_anomaly(f"exception: {type(exc).__name__}: {str(exc)[:200]}")

    def _extend_chain(self, action_summary: str) -> None:
        token = get_token()
        if token is None:
            return

        max_hops = self._scope.max_hops
        if max_hops is not None and self._hop_seq >= max_hops:
            logger.warning("HDP max_hops (%d) reached — skipping hop", max_hops)
            return

        self._hop_seq += 1
        unsigned_hop: dict = {
            "seq": self._hop_seq,
            "agent_id": "llama-index-agent",
            "agent_type": "tool-executor",
            "timestamp": int(time.time() * 1000),
            "action_summary": action_summary,
            "parent_hop": self._hop_seq - 1,
        }

        current_chain: list = token.get("chain", [])
        cumulative = [*current_chain, unsigned_hop]
        hop_sig = sign_hop(cumulative, token["signature"]["value"], self._signing_key)
        signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
        token = {**token, "chain": [*current_chain, signed_hop]}
        set_token(token)
        logger.debug("HDP hop %d recorded: %s", self._hop_seq, action_summary)

    def _record_scope_violation(self, tool: str) -> None:
        token = get_token()
        if token is None:
            return
        scope = token.get("scope", {})
        extensions = scope.get("extensions", {})
        violations: list = extensions.get("scope_violations", [])
        violations.append({"tool": tool, "timestamp": int(time.time() * 1000)})
        token["scope"] = {**scope, "extensions": {**extensions, "scope_violations": violations}}
        set_token(token)

    def _record_anomaly(self, description: str) -> None:
        token = get_token()
        if token is None:
            return
        scope = token.get("scope", {})
        extensions = scope.get("extensions", {})
        anomalies: list = extensions.get("anomalies", [])
        anomalies.append({"description": description, "timestamp": int(time.time() * 1000)})
        token["scope"] = {**scope, "extensions": {**extensions, "anomalies": anomalies}}
        set_token(token)

    def _build_principal_dict(self) -> dict:
        d: dict = {"id": self._principal.id, "id_type": self._principal.id_type}
        if self._principal.display_name is not None:
            d["display_name"] = self._principal.display_name
        if self._principal.metadata is not None:
            d["metadata"] = self._principal.metadata
        return d
