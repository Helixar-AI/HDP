"""HdpMiddleware — non-blocking HDP audit trail for CrewAI crews.

Design considerations implemented:
  #1 Scope enforcement: on_step() inspects AgentAction.tool against authorized_tools.
     In strict mode raises HDPScopeViolationError; otherwise logs and records violation.
  #2 Delegation depth limits: max_hops is enforced in on_task_end().
  #3 Token size / performance: non-blocking throughout; Ed25519 = 64 bytes/hop.
  #4 Verification: see hdp_crewai.verify.verify_chain().
  #5 Memory integration: after_kickoff() persists the token to crewAI's storage path.

Usage:
    from hdp_crewai import HdpMiddleware, ScopePolicy, HdpPrincipal

    middleware = HdpMiddleware(
        signing_key=ed25519_private_key_bytes,
        session_id="session-abc123",
        principal=HdpPrincipal(id="user@example.com", id_type="email"),
        scope=ScopePolicy(
            intent="Analyse sales data and produce weekly summary",
            authorized_tools=["SerperDevTool", "FileReadTool"],
            max_hops=10,
        ),
    )

    crew = Crew(agents=[...], tasks=[...])
    middleware.configure(crew)
    result = crew.kickoff()

    print(middleware.export_token_json())
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
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
    """Non-blocking HDP middleware for CrewAI.

    Hooks into CrewAI's before_kickoff_callbacks, step_callback, task_callback,
    and after_kickoff_callbacks to build a tamper-evident delegation chain.

    All HDP operations are non-blocking by default: failures are logged as
    warnings and crew execution continues unaffected. Set ``strict=True`` to
    have scope violations raise HDPScopeViolationError and halt the crew.
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
        persist_token: bool = True,
    ) -> None:
        self._signing_key = signing_key
        self._session_id = session_id
        self._principal = principal
        self._scope = scope
        self._key_id = key_id
        self._expires_in_ms = expires_in_ms
        self._strict = strict
        self._persist_token = persist_token
        self._token: Optional[dict] = None
        self._hop_seq = 0

    # ------------------------------------------------------------------
    # CrewAI callback entry points
    # ------------------------------------------------------------------

    def before_kickoff(self, inputs: Optional[dict] = None) -> None:
        """Issues the HDP root token. Wired to before_kickoff_callbacks."""
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

    def on_step(self, step_output: Any) -> None:
        """Design consideration #1 — Scope enforcement.

        Called after each agent step via step_callback. Inspects AgentAction.tool
        against scope.authorized_tools.

        - strict=False (default): logs a warning and records the violation in the
          token's scope extensions so it appears in the audit trail.
        - strict=True: raises HDPScopeViolationError, halting the crew.
        """
        # Only check AgentAction objects (not AgentFinish)
        tool = getattr(step_output, "tool", None)
        if tool is None:
            return

        authorized = self._scope.authorized_tools
        if authorized is not None and tool not in authorized:
            if self._strict:
                raise HDPScopeViolationError(tool, authorized)

            logger.warning(
                "HDP scope violation: tool '%s' not in authorized_tools %s",
                tool,
                authorized,
            )
            self._record_scope_violation(tool)

    def on_task_end(self, task_output: Any) -> None:
        """Design consideration #2 — Delegation depth.

        Extends the delegation chain after each task. Wired to task_callback.
        Enforces max_hops — hops beyond the limit are skipped and logged.
        """
        if self._token is None:
            return
        try:
            max_hops = self._scope.max_hops
            if max_hops is not None and self._hop_seq >= max_hops:
                logger.warning(
                    "HDP max_hops (%d) reached — skipping hop for agent '%s'",
                    max_hops,
                    getattr(task_output, "agent", "unknown"),
                )
                return

            self._hop_seq += 1
            agent_id: str = getattr(task_output, "agent", "unknown-agent")
            raw_output: str = str(getattr(task_output, "raw", task_output))
            action_summary = raw_output[:200]

            unsigned_hop: dict = {
                "seq": self._hop_seq,
                "agent_id": agent_id,
                "agent_type": "sub-agent",
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
        except Exception as exc:
            logger.warning("HDP on_task_end failed (non-blocking): %s", exc)

    def after_kickoff(self, output: Any = None) -> Any:
        """Design considerations #3 + #5 — Performance + Memory integration.

        Logs the completed audit trail and, when persist_token=True, writes the
        token JSON to crewAI's storage directory so it can be retrieved for
        retroactive auditing alongside cached task results.
        """
        try:
            if self._token is not None:
                hop_count = len(self._token.get("chain", []))
                logger.info(
                    "HDP audit trail complete — %d hop(s), token %s",
                    hop_count,
                    self._token["header"]["token_id"],
                )
                if self._persist_token:
                    self._save_token_to_storage()
        except Exception as exc:
            logger.warning("HDP after_kickoff failed (non-blocking): %s", exc)
        # after_kickoff_callbacks must return the output unchanged
        return output

    # ------------------------------------------------------------------
    # Convenience: attach this middleware to an existing Crew instance
    # ------------------------------------------------------------------

    def configure(self, crew: Any) -> None:
        """Attach all HDP hooks to a Crew instance.

        Wraps any existing task_callback and step_callback so they are not
        silently replaced.

        Args:
            crew: A crewai.Crew instance.
        """
        crew.before_kickoff_callbacks = [
            *getattr(crew, "before_kickoff_callbacks", []),
            self.before_kickoff,
        ]
        crew.after_kickoff_callbacks = [
            *getattr(crew, "after_kickoff_callbacks", []),
            self.after_kickoff,
        ]

        # Wrap step_callback (scope enforcement — design consideration #1)
        existing_step_cb = getattr(crew, "step_callback", None)
        if existing_step_cb is not None:
            def _chained_step(step_output: Any) -> None:
                existing_step_cb(step_output)
                self.on_step(step_output)
            crew.step_callback = _chained_step
        else:
            crew.step_callback = self.on_step

        # Wrap task_callback (hop recording — design consideration #2)
        existing_task_cb = getattr(crew, "task_callback", None)
        if existing_task_cb is not None:
            def _chained_task(task_output: Any) -> None:
                existing_task_cb(task_output)
                self.on_task_end(task_output)
            crew.task_callback = _chained_task
        else:
            crew.task_callback = self.on_task_end

    # ------------------------------------------------------------------
    # Inspection / export
    # ------------------------------------------------------------------

    def export_token(self) -> Optional[dict]:
        """Return the current token dict, or None if kickoff hasn't run."""
        return self._token

    def export_token_json(self, indent: int = 2) -> Optional[str]:
        """Return the token as a JSON string, or None if kickoff hasn't run."""
        if self._token is None:
            return None
        return json.dumps(self._token, indent=indent)

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

    def _save_token_to_storage(self) -> None:
        """Design consideration #5 — persist token to crewAI's storage directory.

        Stores the HDP token as JSON alongside crewAI's task output database so
        it can be retrieved for retroactive auditing of any stored crew output.
        Falls back silently if the storage path is unavailable.
        """
        try:
            from crewai.utilities.paths import db_storage_path
            storage_dir = Path(db_storage_path())
        except Exception:
            storage_dir = Path.home() / ".crewai"

        try:
            storage_dir.mkdir(parents=True, exist_ok=True)
            token_id = self._token["header"]["token_id"]  # type: ignore[index]
            output_path = storage_dir / f"hdp_token_{token_id}.json"
            output_path.write_text(json.dumps(self._token, indent=2))
            logger.debug("HDP token persisted to %s", output_path)
        except Exception as exc:
            logger.warning("HDP token persistence failed (non-blocking): %s", exc)
