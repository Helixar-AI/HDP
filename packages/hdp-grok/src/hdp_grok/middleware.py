"""HdpMiddleware — stateful HDP integration for Grok / xAI API."""
from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._crypto import extend_token_chain, issue_root_token, verify_token_with_key


class HdpSigningKeyError(Exception):
    """No signing key provided and HDP_SIGNING_KEY env var is absent."""


class HdpTokenMissingError(Exception):
    """extend_chain called before issue_token."""


class HdpTokenExpiredError(Exception):
    """Current token's expires_at has passed."""


def _resolve_key(signing_key: bytes | str | None) -> bytes:
    """Resolve signing_key to raw 32-byte Ed25519 private key bytes."""
    if signing_key is None:
        signing_key = os.getenv("HDP_SIGNING_KEY")
        if not signing_key:
            raise HdpSigningKeyError(
                "No signing_key provided and HDP_SIGNING_KEY env var is not set."
            )

    if isinstance(signing_key, bytes):
        return signing_key

    # str path
    if signing_key.startswith("0x"):
        return bytes.fromhex(signing_key[2:])

    # pure hex string: all hex chars and length matches 32-byte key (64 chars)
    if re.fullmatch(r"[0-9a-fA-F]+", signing_key) and len(signing_key) == 64:
        return bytes.fromhex(signing_key)

    # try base64url, then fallback to hex
    try:
        padding = "=" * (-len(signing_key) % 4)
        return base64.urlsafe_b64decode(signing_key + padding)
    except Exception:
        return bytes.fromhex(signing_key.replace(" ", ""))


class HdpMiddleware:
    """Stateful HDP middleware for Grok / xAI API.

    Manages session state, signing key, and token chain for the lifetime
    of a conversation. Works with the xAI SDK or any OpenAI-compatible client.

    Example::

        import os
        from hdp_grok import HdpMiddleware, get_hdp_tools

        middleware = HdpMiddleware(
            signing_key=os.getenv("HDP_SIGNING_KEY"),
            principal_id="user@example.com",
        )

        # In your tool call loop:
        result = middleware.handle_tool_call(
            name=tool_call.function.name,
            args=json.loads(tool_call.function.arguments),
        )
    """

    def __init__(
        self,
        signing_key: bytes | str | None = None,
        key_id: str = "default",
        default_expires_in: int = 3600,
        session_id: str | None = None,
        principal_id: str | None = None,
    ) -> None:
        self.signing_key: bytes = _resolve_key(signing_key)
        self.key_id = key_id
        self.default_expires_in = default_expires_in
        self.session_id: str = session_id or str(uuid.uuid4())
        self.principal_id: Optional[str] = principal_id

        # Derive public key once at init for use in verify_token
        self._public_key_bytes: bytes = (
            Ed25519PrivateKey.from_private_bytes(self.signing_key)
            .public_key()
            .public_bytes_raw()
        )

        self._current_token: Optional[dict] = None
        self._hop_count: int = 0

    # ── Token lifecycle ──────────────────────────────────────────────────────

    def issue_token(
        self,
        scope: list[str] | None = None,
        expires_in: int | None = None,
    ) -> dict:
        """Issue (or re-issue) the root HDP token.

        Returns:
            {"token": "<json_string>"}
        """
        if not self.principal_id:
            raise ValueError(
                "principal_id must be set at HdpMiddleware.__init__() before calling issue_token()."
            )
        token = issue_root_token(
            signing_key=self.signing_key,
            key_id=self.key_id,
            session_id=self.session_id,
            principal_id=self.principal_id,
            scope=scope or [],
            expires_in=expires_in if expires_in is not None else self.default_expires_in,
        )
        self._current_token = token
        self._hop_count = 0
        return {"token": json.dumps(token)}

    def extend_chain(
        self,
        delegatee_id: str,
        additional_scope: list[str] | None = None,
    ) -> dict:
        """Extend the internal delegation chain by one hop.

        Returns:
            {"new_token": "<json_string>"}
        """
        if self._current_token is None:
            raise HdpTokenMissingError(
                "No current token. Call issue_token() before extend_chain()."
            )
        now_ms = int(time.time() * 1000)
        expires_at = self._current_token.get("header", {}).get("expires_at", 0)
        if now_ms > expires_at:
            raise HdpTokenExpiredError(
                f"Current HDP token expired at {expires_at}. Call issue_token() to rotate."
            )

        new_token = extend_token_chain(
            parent_token=self._current_token,
            signing_key=self.signing_key,
            key_id=self.key_id,
            delegatee_id=delegatee_id,
            additional_scope=additional_scope or [],
        )
        self._current_token = new_token
        self._hop_count += 1
        return {"new_token": json.dumps(new_token)}

    def verify_token(self, token: str) -> dict:
        """Verify a token string using the middleware's own public key."""
        return verify_token_with_key(token, self._public_key_bytes)

    def reset(self) -> None:
        """Clear the current token and hop counter. session_id and principal_id kept."""
        self._current_token = None
        self._hop_count = 0

    # ── Dispatch ─────────────────────────────────────────────────────────────

    def handle_tool_call(self, name: str, args: dict) -> dict:
        """Route any hdp_* tool call to the correct method.

        Handles both snake_case and camelCase argument keys from Grok.
        Raises ValueError for unrecognised tool names.
        """
        if name == "hdp_issue_token":
            return self.issue_token(
                scope=args.get("scope"),
                expires_in=args.get("expires_in"),
            )
        if name == "hdp_extend_chain":
            delegatee_id = args.get("delegatee_id") or args.get("delegateeId")
            additional_scope = args.get("additional_scope") or args.get("additionalScope")
            return self.extend_chain(
                delegatee_id=delegatee_id,
                additional_scope=additional_scope,
            )
        if name == "hdp_verify_token":
            token = args.get("token")
            if not token:
                raise ValueError("hdp_verify_token requires a 'token' argument.")
            return self.verify_token(token)
        raise ValueError(
            f"Unknown HDP tool call: '{name}'. "
            "Supported: hdp_issue_token, hdp_extend_chain, hdp_verify_token"
        )

    # ── Inspection ───────────────────────────────────────────────────────────

    def export_current_token(self) -> dict | None:
        """Return the live in-memory token dict, or None before issue_token."""
        return self._current_token

    def __repr__(self) -> str:
        valid = self._current_token is not None
        return (
            f"HdpMiddleware("
            f"session_id='{self.session_id}', "
            f"hops={self._hop_count}, "
            f"valid={valid}"
            f")"
        )
