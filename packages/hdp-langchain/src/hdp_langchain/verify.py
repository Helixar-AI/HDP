"""Offline chain verification utilities for HDP tokens.

Design consideration #4: Verification Endpoint
Enables downstream systems to validate a complete delegation chain using
only the human's public key. Returns a structured result with validity
status, per-hop outcomes, violations, and depth metrics.

Usage:
    from hdp_langchain import verify_chain

    result = verify_chain(token_dict, public_key_bytes)
    if result.valid:
        print(f"Chain verified: {result.hop_count} hops")
    else:
        print(f"Violations: {result.violations}")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._crypto import verify_hop, verify_root


@dataclass
class HopVerification:
    """Per-hop verification outcome."""
    seq: int
    agent_id: str
    valid: bool
    reason: str = ""


@dataclass
class VerificationResult:
    """Result of verifying an HDP token's complete delegation chain."""
    valid: bool
    token_id: str
    session_id: str
    hop_count: int
    hop_results: list[HopVerification] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return self.hop_count


def verify_chain(token: dict, public_key: Ed25519PublicKey | bytes) -> VerificationResult:
    """Verify a complete HDP token — root signature and every hop in the chain.

    Args:
        token:      A token dict as returned by ``HdpMiddleware.export_token()``.
        public_key: The human's Ed25519 public key. Pass either an
                    ``Ed25519PublicKey`` instance or the raw 32-byte public key
                    bytes (as produced by ``Ed25519PrivateKey.public_key().public_bytes_raw()``).

    Returns:
        VerificationResult with ``valid=True`` only if every signature checks out
        and no structural violations are detected.
    """
    if isinstance(public_key, (bytes, bytearray)):
        pub = _load_raw_public_key(public_key)
    else:
        pub = public_key

    token_id = token.get("header", {}).get("token_id", "unknown")
    session_id = token.get("header", {}).get("session_id", "unknown")
    chain: list[dict] = token.get("chain", [])
    violations: list[str] = []
    hop_results: list[HopVerification] = []

    # 1. Verify root signature
    if not verify_root(token, pub):
        violations.append("Root signature invalid")
        return VerificationResult(
            valid=False,
            token_id=token_id,
            session_id=session_id,
            hop_count=len(chain),
            violations=violations,
        )

    # 2. Check token expiry
    expires_at = token.get("header", {}).get("expires_at", 0)
    now_ms = int(time.time() * 1000)
    if expires_at and now_ms > expires_at:
        violations.append(f"Token expired at {expires_at}")

    # 3. Check max_hops
    max_hops = token.get("scope", {}).get("max_hops")
    if max_hops is not None and len(chain) > max_hops:
        violations.append(f"Chain depth {len(chain)} exceeds max_hops {max_hops}")

    # 4. Verify each hop signature over the cumulative chain
    root_sig_value: str = token["signature"]["value"]
    for i, hop in enumerate(chain):
        hop_sig = hop.get("hop_signature", "")
        unsigned_hop = {k: v for k, v in hop.items() if k != "hop_signature"}
        prior_signed = chain[:i]
        cumulative = [*prior_signed, unsigned_hop]

        ok = verify_hop(cumulative, root_sig_value, hop_sig, pub)
        hop_results.append(HopVerification(
            seq=hop.get("seq", i + 1),
            agent_id=hop.get("agent_id", "unknown"),
            valid=ok,
            reason="" if ok else "Hop signature invalid",
        ))
        if not ok:
            violations.append(f"Hop {hop.get('seq', i + 1)} ({hop.get('agent_id', '?')}) signature invalid")

    # 5. Check sequential seq numbers
    for j, hop in enumerate(chain):
        if hop.get("seq") != j + 1:
            violations.append(f"Non-sequential seq at position {j}: expected {j + 1}, got {hop.get('seq')}")

    valid = len(violations) == 0
    return VerificationResult(
        valid=valid,
        token_id=token_id,
        session_id=session_id,
        hop_count=len(chain),
        hop_results=hop_results,
        violations=violations,
    )


def _load_raw_public_key(raw_bytes: bytes) -> Ed25519PublicKey:
    import cryptography.hazmat.primitives.asymmetric.ed25519 as _ed
    return _ed.Ed25519PublicKey.from_public_bytes(raw_bytes)
