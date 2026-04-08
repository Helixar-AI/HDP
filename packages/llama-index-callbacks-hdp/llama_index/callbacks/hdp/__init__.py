"""HDP integration for LlamaIndex — cryptographic authorization provenance."""

from ._types import DataClassification, HdpPrincipal, HdpScope, HdpToken, HopRecord
from .callbacks import HdpCallbackHandler, HDPScopeViolationError, ScopePolicy
from .instrumentation import HdpInstrumentationHandler
from .postprocessor import HdpNodePostprocessor
from .session import clear_token, get_token, set_token
from .verify import HopVerification, VerificationResult, verify_chain

__all__ = [
    # Core types
    "DataClassification",
    "HdpPrincipal",
    "HdpScope",
    "HdpToken",
    "HopRecord",
    # Policy
    "ScopePolicy",
    "HDPScopeViolationError",
    # Integration layers
    "HdpCallbackHandler",
    "HdpInstrumentationHandler",
    "HdpNodePostprocessor",
    # Session
    "get_token",
    "set_token",
    "clear_token",
    # Verification
    "verify_chain",
    "VerificationResult",
    "HopVerification",
]
