# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""hdp-agent-framework — HDP delegation provenance middleware for Microsoft agent-framework."""

from ._types import DataClassification, HdpPrincipal, HdpScope, HdpToken, HopRecord
from .middleware import HDPScopeViolationError, HdpMiddleware, ScopePolicy
from .verify import HopVerification, VerificationResult, verify_chain

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
