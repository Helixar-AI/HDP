"""Cryptographic primitives for HDP — Ed25519 signing/verification with RFC 8785 canonical JSON.

Matches the HDP v0.1 signing payloads:
  - Root: canonicalize({hdp, header, principal, scope, chain: []}) → Ed25519 → base64url
  - Hop:  canonicalize([root_sig_value, ...cumulative_chain]) → Ed25519 → base64url
"""

from __future__ import annotations

import base64
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _b64url(sig_bytes: bytes) -> str:
    """Encode bytes as unpadded base64url (matches Buffer.toString('base64url') in Node)."""
    return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def _canonicalize(obj: Any) -> bytes:
    """RFC 8785 canonical JSON bytes."""
    return jcs.canonicalize(obj)


def sign_root(unsigned_token: dict, private_key_bytes: bytes, kid: str) -> dict:
    """Sign the canonical unsigned token with an empty chain."""
    payload = {f: unsigned_token[f] for f in ["hdp", "header", "principal", "scope"]}
    payload["chain"] = []
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = key.sign(message)
    return {
        "alg": "Ed25519",
        "kid": kid,
        "value": _b64url(sig_bytes),
    }


def sign_hop(cumulative_chain: list[dict], root_sig_value: str, private_key_bytes: bytes) -> str:
    """Sign a hop over the cumulative chain + root signature value."""
    payload = [root_sig_value, *cumulative_chain]
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = key.sign(message)
    return _b64url(sig_bytes)


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded base64url string to bytes."""
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def verify_root(token: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify the root signature over the canonical unsigned token."""
    try:
        if token["signature"].get("alg") != "Ed25519":
            return False
        payload = {f: token[f] for f in ["hdp", "header", "principal", "scope"]}
        payload["chain"] = []
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(token["signature"]["value"])
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, KeyError, Exception):
        return False


def verify_hop(cumulative_chain: list[dict], root_sig_value: str, hop_signature: str, public_key: Ed25519PublicKey) -> bool:
    """Verify a single hop signature over the cumulative chain + root sig value."""
    try:
        payload = [root_sig_value, *cumulative_chain]
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(hop_signature)
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, Exception):
        return False
