"""hdp-autogen — HDP delegation provenance middleware for AutoGen."""

from ._types import HdpPrincipal, HdpScope, HdpToken, HopRecord, DataClassification
from .middleware import HdpMiddleware, ScopePolicy, HDPScopeViolationError
from .verify import verify_chain, VerificationResult, HopVerification

__all__ = [
    "HdpMiddleware",
    "ScopePolicy",
    "HDPScopeViolationError",
    "HdpPrincipal",
    "HdpScope",
    "HdpToken",
    "HopRecord",
    "DataClassification",
    "verify_chain",
    "VerificationResult",
    "HopVerification",
]
