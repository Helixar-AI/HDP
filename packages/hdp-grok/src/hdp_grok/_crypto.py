"""Cryptographic primitives for hdp-grok — Ed25519 + RFC 8785.

Low-level helpers (_b64url, _canonicalize, sign_root, sign_hop, verify_root,
verify_hop) are copied verbatim from hdp-crewai/_crypto.py and share the same
wire format.

High-level functions (issue_root_token, extend_token_chain,
verify_token_with_key) are the public contract for HdpMiddleware.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# ── Low-level helpers (wire-format compatible with hdp-crewai) ────────────────

def _b64url(sig_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def _canonicalize(obj: Any) -> bytes:
    return jcs.canonicalize(obj)


def _sign_root(unsigned_token: dict, private_key_bytes: bytes, kid: str) -> dict:
    subset = {f: unsigned_token[f] for f in ["header", "principal", "scope"] if f in unsigned_token}
    message = _canonicalize(subset)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = key.sign(message)
    return {
        "alg": "Ed25519",
        "kid": kid,
        "value": _b64url(sig_bytes),
        "signed_fields": ["header", "principal", "scope"],
    }


def _sign_hop(cumulative_chain: list[dict], root_sig_value: str, private_key_bytes: bytes) -> str:
    payload = {"chain": cumulative_chain, "root_sig": root_sig_value}
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return _b64url(key.sign(message))


def _verify_root(token: dict, public_key: Ed25519PublicKey) -> bool:
    try:
        subset = {f: token[f] for f in ["header", "principal", "scope"] if f in token}
        message = _canonicalize(subset)
        sig_bytes = _b64url_decode(token["signature"]["value"])
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


def _verify_hop(
    cumulative_chain: list[dict],
    root_sig_value: str,
    hop_signature: str,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        payload = {"chain": cumulative_chain, "root_sig": root_sig_value}
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(hop_signature)
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


# ── High-level functions used by HdpMiddleware ────────────────────────────────

def issue_root_token(
    signing_key: bytes,
    key_id: str,
    session_id: str,
    principal_id: str,
    scope: list[str],
    expires_in: int,
) -> dict:
    """Build and sign a root HDP token dict."""
    now = int(time.time() * 1000)
    unsigned: dict = {
        "hdp": "0.1",
        "header": {
            "token_id": str(uuid.uuid4()),
            "issued_at": now,
            "expires_at": now + expires_in * 1000,
            "session_id": session_id,
            "version": "0.1",
        },
        "principal": {
            "id": principal_id,
            "id_type": "opaque",
        },
        "scope": {
            "intent": principal_id,
            "data_classification": "internal",
            "network_egress": True,
            "persistence": False,
            "authorized_tools": scope,
        },
        "chain": [],
    }
    signature = _sign_root(unsigned, signing_key, key_id)
    return {**unsigned, "signature": signature}


def extend_token_chain(
    parent_token: dict,
    signing_key: bytes,
    key_id: str,
    delegatee_id: str,
    additional_scope: list[str],
) -> dict:
    """Append a signed hop to parent_token and return the updated dict."""
    current_chain: list = parent_token.get("chain", [])
    hop_seq = len(current_chain) + 1
    unsigned_hop: dict = {
        "seq": hop_seq,
        "agent_id": delegatee_id,
        "agent_type": "sub-agent",
        "timestamp": int(time.time() * 1000),
        "action_summary": "",
        "parent_hop": hop_seq - 1,
    }
    cumulative = [*current_chain, unsigned_hop]
    hop_sig = _sign_hop(cumulative, parent_token["signature"]["value"], signing_key)
    signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
    return {**parent_token, "chain": [*current_chain, signed_hop]}


def verify_token_with_key(token_str: str, public_key_bytes: bytes) -> dict:
    """Verify a JSON token string against a 32-byte Ed25519 public key."""
    try:
        token = json.loads(token_str)
    except json.JSONDecodeError:
        return {"valid": False, "hop_count": 0, "principal_id": None,
                "session_id": None, "expires_at": 0, "expired": False,
                "violations": ["invalid JSON"], "chain": []}

    pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    now_ms = int(time.time() * 1000)
    expires_at: int = token.get("header", {}).get("expires_at", 0)
    expired = now_ms > expires_at

    root_ok = _verify_root(token, pub_key)
    chain: list[dict] = token.get("chain", [])
    hop_ok = True
    root_sig_value = token.get("signature", {}).get("value", "")

    for i, hop in enumerate(chain):
        hop_sig = hop.get("hop_signature", "")
        # Signing payload: prior hops WITH their hop_signature + current hop WITHOUT hop_signature.
        # This matches the signing side: sign_hop received the current hop before hop_signature
        # was set, so the payload must exclude it from the current hop during verification.
        unsigned_current = {k: v for k, v in hop.items() if k != "hop_signature"}
        cumulative = [*chain[:i], unsigned_current]
        if not _verify_hop(cumulative, root_sig_value, hop_sig, pub_key):
            hop_ok = False
            break

    violations: list[str] = token.get("scope", {}).get("extensions", {}).get("scope_violations", [])

    return {
        "valid": root_ok and hop_ok,
        "hop_count": len(chain),
        "principal_id": token.get("principal", {}).get("id"),
        "session_id": token.get("header", {}).get("session_id"),
        "expires_at": expires_at,
        "expired": expired,
        "violations": violations,
        "chain": chain,
    }
