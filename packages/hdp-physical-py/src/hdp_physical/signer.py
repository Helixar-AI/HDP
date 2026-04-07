"""Ed25519 signing and verification for EdtToken."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from hdp_physical.types import EdtToken, SignedEdt


# ---------------------------------------------------------------------------
# Canonical JSON (RFC-8785-style: sorted keys, no whitespace)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> str:
    """Produce deterministic JSON with sorted keys (recursive)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _edt_to_dict(edt: EdtToken) -> dict:
    """Convert EdtToken to a plain dict with int enum values serialised as ints."""
    d = edt.model_dump()
    # IrreversibilityClass is an IntEnum — model_dump already gives the int value
    return d


def canonicalize_edt(edt: EdtToken) -> str:
    """Return canonical JSON string for an EdtToken."""
    return _canonical(_edt_to_dict(edt))


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------


async def sign_edt(edt: EdtToken, private_key: Ed25519PrivateKey, kid: str) -> SignedEdt:
    """Sign *edt* with *private_key* and return a :class:`SignedEdt`."""
    canonical = canonicalize_edt(edt)
    msg_bytes = canonical.encode("utf-8")
    sig_bytes = private_key.sign(msg_bytes)
    signature = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
    return SignedEdt(edt=edt, signature=signature, kid=kid, alg="Ed25519")


async def verify_edt(signed_edt: SignedEdt, public_key: Ed25519PublicKey) -> bool:
    """Verify the signature of *signed_edt*.  Returns ``True`` if valid."""
    try:
        canonical = canonicalize_edt(signed_edt.edt)
        msg_bytes = canonical.encode("utf-8")
        # Restore padding
        sig_b64 = signed_edt.signature + "=" * (-len(signed_edt.signature) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig_b64)
        public_key.verify(sig_bytes, msg_bytes)
        return True
    except (InvalidSignature, Exception):
        return False
