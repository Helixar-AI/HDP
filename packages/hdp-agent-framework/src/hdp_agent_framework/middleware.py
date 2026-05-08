# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""HdpMiddleware — non-blocking HDP audit trail for agent-framework agents.

Design considerations implemented:
  #1 Scope enforcement: _function_middleware() inspects tool calls against
     authorized_tools. In strict mode raises HDPScopeViolationError; otherwise
     logs and records violation.
  #2 Delegation depth limits: max_hops is enforced in _extend_chain().
  #3 Token size / performance: non-blocking throughout; Ed25519 = 64 bytes/hop.
  #4 Verification: see hdp_agent_framework.verify.verify_chain().

Usage:
    from hdp_agent_framework import HdpMiddleware, ScopePolicy, HdpPrincipal

    middleware = HdpMiddleware(
        signing_key=ed25519_private_key_bytes,
        session_id="session-abc123",
        principal=HdpPrincipal(id="user@example.com", id_type="email"),
        scope=ScopePolicy(
            intent="Coordinate research agents",
            authorized_tools=["web_search", "file_reader"],
            max_hops=10,
        ),
    )

    # Attach to an agent
    middleware.configure(agent)

    # After the run completes
    print(middleware.export_token_json())
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

from ._crypto import sign_hop, sign_root
from ._types import DataClassification, HdpPrincipal

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
    """Non-blocking HDP middleware for agent-framework.

    Hooks into agent-framework's ChatMiddleware protocol to build a
    tamper-evident delegation chain.

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
        expires_in_ms: int = 86_400_000,
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
    # ChatMiddleware protocol
    # ------------------------------------------------------------------

    async def process(self, context: Any, call_next: Any) -> None:
        """Chat middleware entry point.

        1. Lazily issue root token if not yet done.
        2. Extract agent_id from context.metadata.get("agent_name", "unknown").
        3. Extend the chain with one hop.
        4. await call_next().
        """
        if self._token is None:
            self._issue_root_token()

        try:
            agent_id = context.metadata.get("agent_name", "unknown")
            action_summary = context.metadata.get("action_summary", "")
            self._extend_chain(
                agent_id=agent_id,
                action_summary=action_summary,
                agent_type="sub-agent",
            )
        except Exception as exc:
            logger.warning("HDP process failed (non-blocking): %s", exc)

        await call_next()

    async def _function_middleware(self, context: Any, call_next: Any) -> None:
        """Function/tool middleware entry point.

        1. Get tool name from context.function.name.
        2. If authorized_tools is None: await call_next() and return.
        3. If tool NOT in authorized_tools:
             If strict=True: raise HDPScopeViolationError.
             Else: record violation in token, then await call_next().
        4. Else (authorized): await call_next().
        """
        tool_name = context.function.name
        authorized = self._scope.authorized_tools

        if authorized is None:
            await call_next()
            return

        if tool_name not in authorized:
            if self._strict:
                raise HDPScopeViolationError(tool_name, authorized)
            logger.warning(
                "HDP scope violation: tool '%s' not in authorized_tools %s",
                tool_name,
                authorized,
            )
            self._record_scope_violation(tool_name)

        await call_next()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, target: Any) -> None:
        """Attach HDP middleware to an agent-framework agent.

        If the target has a .middleware attribute (a list), appends
        self and self._function_middleware if not already present.
        Otherwise logs a warning.
        """
        if hasattr(target, "middleware") and isinstance(target.middleware, list):
            if self not in target.middleware:
                target.middleware.append(self)
            if self._function_middleware not in target.middleware:
                target.middleware.append(self._function_middleware)
        else:
            logger.warning(
                "HDP configure: target %s has no .middleware list — no hooks attached",
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
    # Internal: root token issuance
    # ------------------------------------------------------------------

    def _issue_root_token(self) -> None:
        """Issue the HDP root token. Called lazily on first process() call."""
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
            logger.warning("HDP _issue_root_token failed (non-blocking): %s", exc)
            # Leave self._token as None — non-blocking design

    # ------------------------------------------------------------------
    # Internal: chain extension
    # ------------------------------------------------------------------

    def _extend_chain(self, agent_id: str, action_summary: str = "", agent_type: str = "sub-agent") -> None:
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
    # Internal: scope violation recording
    # ------------------------------------------------------------------

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
