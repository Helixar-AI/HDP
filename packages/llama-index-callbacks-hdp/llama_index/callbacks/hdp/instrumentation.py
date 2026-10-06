"""HdpInstrumentationHandler — modern instrumentation dispatcher integration for LlamaIndex.

For LlamaIndex >=0.10.20. Hooks into the root instrumentation dispatcher via
BaseEventHandler and BaseSpanHandler.

Usage:
    from llama_index.callbacks.hdp import HdpInstrumentationHandler, HdpPrincipal, ScopePolicy

    HdpInstrumentationHandler.init(
        signing_key=ed25519_private_key_bytes,
        principal=HdpPrincipal(id="alice@corp.com", id_type="email"),
        scope=ScopePolicy(
            intent="Research pipeline",
            authorized_tools=["web_search", "retriever"],
        ),
        on_token_ready=lambda token: print(token["header"]["token_id"]),
    )

    # Run your query engine / agent as normal. The root dispatcher captures all events.
"""

from __future__ import annotations

from copy import deepcopy
import logging
import time
import uuid
from typing import Any, Callable, Optional, Type

from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llama_index.core.instrumentation.events import BaseEvent
from llama_index.core.instrumentation.events.agent import (
    AgentRunStepEndEvent,
    AgentRunStepStartEvent,
    AgentToolCallEvent,
)
from llama_index.core.instrumentation.events.llm import (
    LLMChatEndEvent,
    LLMChatStartEvent,
)
from llama_index.core.instrumentation.events.query import (
    QueryEndEvent,
    QueryStartEvent,
)
from llama_index.core.instrumentation.span_handlers import BaseSpanHandler
from llama_index.core.instrumentation.span import BaseSpan

from ._crypto import sign_hop, sign_root
from ._types import DataClassification, HdpPrincipal
from .callbacks import HDPScopeViolationError, ScopePolicy
from .session import get_token, set_token
from .verify import _validate_token_input

logger = logging.getLogger(__name__)


class _HdpSpan(BaseSpan):
    """Minimal span that carries the HDP token ID for trace correlation."""
    hdp_token_id: Optional[str] = None


class HdpSpanHandler(BaseSpanHandler[_HdpSpan]):
    """Tags each span with the active HDP token ID for cross-tool trace correlation."""

    def new_span(
        self,
        id_: str,
        bound_args: Any,
        instance: Optional[Any] = None,
        parent_span_id: Optional[str] = None,
        tags: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[_HdpSpan]:
        try:
            token = get_token()
            token_id = token["header"]["token_id"] if token else None
            return _HdpSpan(
                id_=id_,
                parent_id=parent_span_id,
                tags={**(tags or {}), "hdp_token_id": token_id},
                hdp_token_id=token_id,
            )
        except Exception as exc:
            logger.debug("HDP span creation failed (non-blocking): %s", exc)
            return None

    def prepare_to_exit_span(
        self,
        id_: str,
        bound_args: Any,
        instance: Optional[Any] = None,
        result: Optional[Any] = None,
        **kwargs: Any,
    ) -> Optional[_HdpSpan]:
        return self.open_spans.get(id_)

    def prepare_to_drop_span(
        self,
        id_: str,
        bound_args: Any,
        instance: Optional[Any] = None,
        err: Optional[BaseException] = None,
        **kwargs: Any,
    ) -> Optional[_HdpSpan]:
        span = self.open_spans.get(id_)
        if span is not None:
            logger.debug(
                "HDP span dropped: %s (token: %s, error: %s)",
                id_,
                span.hdp_token_id,
                err,
            )
        return span


class HdpEventHandler(BaseEventHandler):
    """Routes LlamaIndex instrumentation events to HDP chain operations."""

    def __init__(
        self,
        signing_key: bytes,
        principal: HdpPrincipal,
        scope: ScopePolicy,
        key_id: str,
        expires_in_ms: int,
        on_token_ready: Optional[Callable[[dict], None]],
    ) -> None:
        self._signing_key = signing_key
        self._principal = principal
        self._scope = scope
        self._key_id = key_id
        self._expires_in_ms = expires_in_ms
        self._on_token_ready = on_token_ready
        self._hop_seq = 0

    @classmethod
    def class_name(cls) -> str:
        return "HdpEventHandler"

    def handle(self, event: BaseEvent, **kwargs: Any) -> None:
        try:
            if isinstance(event, QueryStartEvent):
                self._on_query_start(event)
            elif isinstance(event, AgentToolCallEvent):
                self._on_tool_call(event)
            elif isinstance(event, LLMChatStartEvent):
                self._on_llm_start(event)
            elif isinstance(event, LLMChatEndEvent):
                self._on_llm_end(event)
            elif isinstance(event, QueryEndEvent):
                self._on_query_end(event)
        except Exception:
            logger.warning("HDP event recording failed; action continues")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_query_start(self, event: QueryStartEvent) -> None:
        session_id = str(event.id_) if event.id_ else str(uuid.uuid4())
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
        candidate = {**unsigned, "signature": {"alg": "Ed25519", "kid": self._key_id, "value": "A" * 86}}
        input_error = _validate_token_input(candidate)
        if input_error is not None:
            raise ValueError(input_error)
        try:
            signature = sign_root(unsigned, self._signing_key, self._key_id)
            token = {**unsigned, "signature": signature}
            set_token(token)
            self._hop_seq = 0
            logger.debug("HDP root token issued: %s", token["header"]["token_id"])
        except Exception:
            logger.warning("HDP root record signing failed; action continues")

    def _on_tool_call(self, event: AgentToolCallEvent) -> None:
        tool_name: str = ""
        if hasattr(event, "tool") and event.tool is not None:
            tool_name = getattr(event.tool, "name", str(event.tool))
        elif hasattr(event, "tool_name"):
            tool_name = str(event.tool_name)
        tool_name = tool_name or "unknown-tool"

        authorized = self._scope.authorized_tools
        out_of_scope = authorized is not None and tool_name not in authorized
        if out_of_scope:
            logger.warning(
                "HDP scope violation: tool '%s' not in authorized_tools %s",
                tool_name,
                authorized,
            )
        summary = (
            f"attempted out-of-scope tool call: {tool_name}"
            if out_of_scope
            else f"tool_call: {tool_name}"
        )
        self._extend_chain(action_summary=summary)

    def _on_llm_start(self, event: LLMChatStartEvent) -> None:
        model_name: str = ""
        if hasattr(event, "model_dict") and event.model_dict:
            model_name = str(event.model_dict.get("model", ""))
        if model_name:
            self._extend_chain(action_summary=f"observed model invocation: {model_name}")

    def _on_llm_end(self, event: LLMChatEndEvent) -> None:
        pass  # token lifecycle managed by query events

    def _on_query_end(self, event: QueryEndEvent) -> None:
        token = get_token()
        if token is not None and self._on_token_ready is not None:
            try:
                self._on_token_ready(token)
            except Exception:
                logger.warning("HDP token-ready callback failed")

    # ------------------------------------------------------------------
    # Helpers (shared with HdpCallbackHandler logic)
    # ------------------------------------------------------------------

    def _extend_chain(self, action_summary: str) -> None:
        try:
            token = get_token()
            if token is None:
                return

            max_hops = self._scope.max_hops
            if max_hops is not None and self._hop_seq >= max_hops:
                logger.warning("HDP max_hops (%d) reached; hop was not recorded", max_hops)
                return
            input_error = _validate_token_input(token)
            if input_error is not None:
                raise ValueError(input_error)

            next_seq = self._hop_seq + 1
            unsigned_hop: dict = {
                "seq": next_seq,
                "agent_id": "llama-index-agent",
                "agent_type": "tool-executor",
                "timestamp": int(time.time() * 1000),
                "action_summary": action_summary,
                "parent_hop": next_seq - 1,
            }

            current_chain: list = token.get("chain", [])
            candidate = {
                **token,
                "chain": [*current_chain, {**unsigned_hop, "hop_signature": "A" * 86}],
            }
            input_error = _validate_token_input(candidate)
            if input_error is not None:
                raise ValueError(input_error)

            cumulative = [*current_chain, unsigned_hop]
            hop_sig = sign_hop(cumulative, token["signature"]["value"], self._signing_key)
            signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
            set_token({**token, "chain": [*current_chain, signed_hop]})
            self._hop_seq = next_seq
            logger.debug("HDP hop %d recorded", next_seq)
        except Exception:
            logger.warning("HDP audit record append failed; action continues")

    def _record_scope_violation(self, tool: str) -> None:
        self._extend_chain(action_summary=f"attempted out-of-scope tool call: {tool}")

    def _build_principal_dict(self) -> dict:
        d: dict = {"id": self._principal.id, "id_type": self._principal.id_type}
        if self._principal.display_name is not None:
            d["display_name"] = self._principal.display_name
        if self._principal.metadata is not None:
            d["metadata"] = self._principal.metadata
        return d


class HdpInstrumentationHandler:
    """Entry point for the modern LlamaIndex instrumentation integration.

    Call HdpInstrumentationHandler.init() once at application startup.
    It wires HdpEventHandler and HdpSpanHandler to the root dispatcher
    so all downstream LlamaIndex activity is captured automatically.
    """

    @classmethod
    def init(
        cls,
        signing_key: bytes,
        principal: HdpPrincipal,
        scope: ScopePolicy,
        key_id: str = "default",
        expires_in_ms: int = 24 * 60 * 60 * 1000,
        on_violation: str = "log",
        on_token_ready: Optional[Callable[[dict], None]] = None,
    ) -> "HdpInstrumentationHandler":
        """Wire HDP handlers to the root LlamaIndex instrumentation dispatcher.

        Args:
            signing_key:    Ed25519 private key bytes.
            principal:      HdpPrincipal identifying the authorizing human.
            scope:          ScopePolicy (intent, authorized_tools, max_hops, etc.).
            key_id:         Key identifier for rotation support.
            expires_in_ms:  Token TTL in milliseconds (default 24h).
            on_violation:   "log" (default). "raise" fails during construction.
            on_token_ready: Optional callback invoked with the final token at query end.

        Returns:
            The HdpInstrumentationHandler instance (holds references to wired handlers).
        """
        if on_violation == "raise":
            raise ValueError("HDP tokens are records and cannot gate actions")

        now = int(time.time() * 1000)
        candidate = {
            "hdp": "0.1",
            "header": {
                "token_id": str(uuid.uuid4()),
                "issued_at": now,
                "expires_at": now + expires_in_ms,
                "session_id": "validation-session",
                "version": "0.1",
            },
            "principal": {
                "id": principal.id,
                "id_type": principal.id_type,
                **({"display_name": principal.display_name} if principal.display_name is not None else {}),
                **({"metadata": principal.metadata} if principal.metadata is not None else {}),
            },
            "scope": scope.to_dict(),
            "chain": [],
            "signature": {"alg": "Ed25519", "kid": key_id, "value": "A" * 86},
        }
        input_error = _validate_token_input(candidate)
        if input_error is not None:
            raise ValueError(input_error)

        import llama_index.core.instrumentation as instrument

        event_handler = HdpEventHandler(
            signing_key=signing_key,
            principal=principal,
            scope=scope,
            key_id=key_id,
            expires_in_ms=expires_in_ms,
            on_token_ready=on_token_ready,
        )
        span_handler = HdpSpanHandler()

        dispatcher = instrument.get_dispatcher()
        dispatcher.add_event_handler(event_handler)
        dispatcher.add_span_handler(span_handler)

        instance = cls()
        instance._event_handler = event_handler
        instance._span_handler = span_handler
        instance._dispatcher = dispatcher
        return instance

    def export_token(self) -> Optional[dict]:
        """Return a defensive copy of the active token from the ContextVar."""
        return deepcopy(get_token())
