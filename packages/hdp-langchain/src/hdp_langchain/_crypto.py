"""Cryptographic primitives for HDP — Ed25519 signing/verification with RFC 8785 canonical JSON.

Matches the signing scheme in the TypeScript SDK (src/crypto/sign.ts + src/crypto/verify.ts):
  - Root: canonicalize({header, principal, scope}) → Ed25519 → base64url
  - Hop:  canonicalize({chain: [...], root_sig: <value>}) → Ed25519 → base64url

Note: This file is shared across all HDP Python packages (hdp-crewai, hdp-autogen, hdp-grok,
hdp-langchain). The implementation is identical in each — a shared hdp-core package is
a planned future improvement.
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
    """Sign the root token over {header, principal, scope} and return a signature dict."""
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


def sign_hop(cumulative_chain: list[dict], root_sig_value: str, private_key_bytes: bytes) -> str:
    """Sign a hop over the cumulative chain + root signature value."""
    payload = {"chain": cumulative_chain, "root_sig": root_sig_value}
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = key.sign(message)
    return _b64url(sig_bytes)


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded base64url string to bytes."""
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def verify_root(token: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify the root signature over {header, principal, scope}."""
    try:
        subset = {f: token[f] for f in ["header", "principal", "scope"] if f in token}
        message = _canonicalize(subset)
        sig_bytes = _b64url_decode(token["signature"]["value"])
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, KeyError, Exception):
        return False


def verify_hop(cumulative_chain: list[dict], root_sig_value: str, hop_signature: str, public_key: Ed25519PublicKey) -> bool:
    """Verify a single hop signature over the cumulative chain + root sig value."""
    try:
        payload = {"chain": cumulative_chain, "root_sig": root_sig_value}
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(hop_signature)
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, Exception):
        return False
