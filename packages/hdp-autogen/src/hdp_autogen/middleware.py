"""HdpMiddleware — non-blocking HDP audit trail for AutoGen agents.

Design considerations implemented:
  #1 Scope enforcement: _on_message_receive() inspects tool calls against authorized_tools.
     In strict mode raises HDPScopeViolationError; otherwise logs and records violation.
  #2 Delegation depth limits: max_hops is enforced in _extend_chain().
  #3 Token size / performance: non-blocking throughout; Ed25519 = 64 bytes/hop.
  #4 Verification: see hdp_autogen.verify.verify_chain().
  #5 GroupChat integration: configure() hooks into GroupChatManager and ConversableAgent.

Usage:
    from hdp_autogen import HdpMiddleware, ScopePolicy, HdpPrincipal

    middleware = HdpMiddleware(
        signing_key=ed25519_private_key_bytes,
        session_id="session-abc123",
        principal=HdpPrincipal(id="user@example.com", id_type="email"),
        scope=ScopePolicy(
            intent="Coordinate research agents via GroupChat",
            authorized_tools=["web_search", "file_reader"],
            max_hops=10,
        ),
    )

    # ConversableAgent
    middleware.configure(agent)

    # GroupChatManager
    middleware.configure(group_chat_manager)

    # After the chat completes
    print(middleware.export_token_json())
"""

from __future__ import annotations

import functools
import json
import logging
import time
import uuid
from typing import Any, Optional

from ._crypto import sign_hop, sign_root
from ._types import HdpPrincipal, DataClassification

logger = logging.getLogger(__name__)


class HDPScopeViolationError(Exception):
    """Raised when an agent attempts to use a tool outside the authorized scope."""

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
    """Non-blocking HDP middleware for AutoGen.

    Hooks into AutoGen's ConversableAgent hooks and GroupChatManager message
    routing to build a tamper-evident delegation chain.

    All HDP operations are non-blocking by default: failures are logged as
    warnings and agent execution continues unaffected. Set ``strict=True`` to
    have scope violations raise HDPScopeViolationError and halt the agent.
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
        self._signing_key = signing_key
        self._session_id = session_id
        self._principal = principal
        self._scope = scope
        self._key_id = key_id
        self._expires_in_ms = expires_in_ms
        self._strict = strict
        self._token: Optional[dict] = None
        self._hop_seq = 0

    # ------------------------------------------------------------------
    # Root token issuance
    # ------------------------------------------------------------------

    def before_kickoff(self) -> None:
        """Issue the HDP root token. Called automatically by configure() hooks."""
        try:
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
            signature = sign_root(unsigned, self._signing_key, self._key_id)
            self._token = {**unsigned, "signature": signature}
            logger.debug("HDP root token issued: %s", self._token["header"]["token_id"])
        except Exception as exc:
            logger.warning("HDP before_kickoff failed (non-blocking): %s", exc)

    # ------------------------------------------------------------------
    # AutoGen hook callbacks
    # ------------------------------------------------------------------

    def on_message_send(self, sender: Any, message: Any, recipient: Any, silent: bool = False) -> Any:
        """Hook for ConversableAgent process_message_before_send.

        Extends the delegation chain by one hop each time an agent sends a
        message. Each speaker turn in a GroupChat maps to one hop.

        Returns the message unchanged so AutoGen's hook pipeline continues.
        """
        if self._token is None:
            self.before_kickoff()

        try:
            sender_name = getattr(sender, "name", None) or str(sender)
            content = _extract_content(message)
            self._extend_chain(
                agent_id=sender_name,
                action_summary=content[:200],
                agent_type="sub-agent",
            )
        except Exception as exc:
            logger.warning("HDP on_message_send failed (non-blocking): %s", exc)

        return message

    def on_message_receive(self, sender: Any, message: Any, recipient: Any, silent: bool = False) -> Any:
        """Hook for scope enforcement on incoming messages.

        Inspects tool calls in the message and validates them against
        authorized_tools. In strict mode, raises HDPScopeViolationError.

        Returns the message unchanged so AutoGen's hook pipeline continues.
        """
        tools = _extract_tool_calls(message)
        authorized = self._scope.authorized_tools
        if authorized is None:
            return message

        for tool in tools:
            if tool not in authorized:
                if self._strict:
                    raise HDPScopeViolationError(tool, authorized)
                logger.warning(
                    "HDP scope violation: tool '%s' not in authorized_tools %s",
                    tool,
                    authorized,
                )
                self._record_scope_violation(tool)

        return message

    # ------------------------------------------------------------------
    # Convenience: attach this middleware to an AutoGen agent or manager
    # ------------------------------------------------------------------

    def configure(self, target: Any) -> None:
        """Attach all HDP hooks to an AutoGen agent or GroupChatManager.

        Supports:
          - ConversableAgent (v0.4+): registers process_message_before_send
            and process_last_received_message hooks.
          - GroupChatManager: wraps run_chat to issue root token and record
            each speaker turn as a delegation hop.
          - List of agents: configures each agent in the list.

        Chains existing hooks — never silently replaces them.

        Args:
            target: A ConversableAgent, GroupChatManager, or list of agents.
        """
        if isinstance(target, (list, tuple)):
            for agent in target:
                self.configure(agent)
            return

        # GroupChatManager detection: has _groupchat attribute
        if hasattr(target, "_groupchat"):
            self._configure_group_chat_manager(target)
            return

        # ConversableAgent detection: has register_hook method
        if hasattr(target, "register_hook"):
            self._configure_conversable_agent(target)
            return

        logger.warning(
            "HDP configure: unrecognised target type %s — no hooks attached",
            type(target).__name__,
        )

    # ------------------------------------------------------------------
    # Inspection / export
    # ------------------------------------------------------------------

    def export_token(self) -> Optional[dict]:
        """Return the current token dict, or None if no token has been issued."""
        return self._token

    def export_token_json(self, indent: int = 2) -> Optional[str]:
        """Return the token as a JSON string, or None if no token has been issued."""
        if self._token is None:
            return None
        return json.dumps(self._token, indent=indent)

    # ------------------------------------------------------------------
    # Internal: configure helpers
    # ------------------------------------------------------------------

    def _configure_conversable_agent(self, agent: Any) -> None:
        """Attach hooks to a ConversableAgent via register_hook."""
        try:
            agent.register_hook(
                "process_message_before_send",
                self._agent_send_hook,
            )
            agent.register_hook(
                "process_last_received_message",
                self._agent_receive_hook,
            )
            logger.debug("HDP hooks attached to ConversableAgent '%s'", getattr(agent, "name", "?"))
        except Exception as exc:
            logger.warning("HDP configure agent failed (non-blocking): %s", exc)

    def _configure_group_chat_manager(self, manager: Any) -> None:
        """Wrap GroupChatManager.run_chat to intercept speaker turns."""
        original_run_chat = getattr(manager, "run_chat", None)
        if original_run_chat is None:
            logger.warning("HDP configure: GroupChatManager has no run_chat method")
            return

        middleware = self

        @functools.wraps(original_run_chat)
        def _wrapped_run_chat(messages: Any = None, *args: Any, **kwargs: Any) -> Any:
            if middleware._token is None:
                middleware.before_kickoff()
            return original_run_chat(messages, *args, **kwargs)

        manager.run_chat = _wrapped_run_chat

        # Also attach hooks to all agents in the GroupChat
        groupchat = getattr(manager, "_groupchat", None)
        if groupchat is not None:
            agents = getattr(groupchat, "agents", [])
            for agent in agents:
                if hasattr(agent, "register_hook"):
                    self._configure_conversable_agent(agent)

        logger.debug("HDP hooks attached to GroupChatManager")

    # ------------------------------------------------------------------
    # Internal: agent hook adapters
    # ------------------------------------------------------------------

    def _agent_send_hook(self, sender: Any, message: Any, recipient: Any, silent: bool) -> Any:
        """Adapter for ConversableAgent process_message_before_send hook."""
        return self.on_message_send(sender, message, recipient, silent)

    def _agent_receive_hook(self, sender: Any, message: Any, recipient: Any, silent: bool) -> Any:
        """Adapter for ConversableAgent process_last_received_message hook."""
        return self.on_message_receive(sender, message, recipient, silent)

    # ------------------------------------------------------------------
    # Internal: chain extension
    # ------------------------------------------------------------------

    def _extend_chain(self, agent_id: str, action_summary: str, agent_type: str = "sub-agent") -> None:
        """Append a signed hop to the delegation chain.

        Enforces max_hops — hops beyond the limit are skipped and logged.
        """
        if self._token is None:
            return

        max_hops = self._scope.max_hops
        if max_hops is not None and self._hop_seq >= max_hops:
            logger.warning(
                "HDP max_hops (%d) reached — skipping hop for agent '%s'",
                max_hops,
                agent_id,
            )
            return

        self._hop_seq += 1
        unsigned_hop: dict = {
            "seq": self._hop_seq,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "timestamp": int(time.time() * 1000),
            "action_summary": action_summary,
            "parent_hop": self._hop_seq - 1,
        }

        current_chain: list = self._token.get("chain", [])
        cumulative = [*current_chain, unsigned_hop]
        hop_sig = sign_hop(cumulative, self._token["signature"]["value"], self._signing_key)

        signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
        self._token = {**self._token, "chain": [*current_chain, signed_hop]}
        logger.debug("HDP hop %d recorded for agent '%s'", self._hop_seq, agent_id)

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
        """Record a scope violation in the token's scope extensions for audit visibility."""
        if self._token is None:
            return
        scope = self._token.get("scope", {})
        extensions = scope.get("extensions", {})
        violations: list = extensions.get("scope_violations", [])
        violations.append({"tool": tool, "timestamp": int(time.time() * 1000)})
        updated_extensions = {**extensions, "scope_violations": violations}
        self._token = {
            **self._token,
            "scope": {**scope, "extensions": updated_extensions},
        }


# ---------------------------------------------------------------------------
# Message content extraction helpers
# ---------------------------------------------------------------------------

def _extract_content(message: Any) -> str:
    """Extract text content from an AutoGen message (str or dict)."""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        return str(message.get("content", ""))
    return str(message)


def _extract_tool_calls(message: Any) -> list[str]:
    """Extract tool call names from an AutoGen message.

    AutoGen messages may contain tool_calls in several formats:
      - dict with "tool_calls" key (list of {function: {name: ...}})
      - dict with "function_call" key ({name: ...})
    """
    if not isinstance(message, dict):
        return []

    tools: list[str] = []

    # OpenAI-style tool_calls
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for tc in tool_calls:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            name = fn.get("name")
            if name:
                tools.append(name)

    # Legacy function_call
    fn_call = message.get("function_call")
    if isinstance(fn_call, dict):
        name = fn_call.get("name")
        if name:
            tools.append(name)

    return tools
