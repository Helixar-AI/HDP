# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Helixar Limited
"""hdp-agent-framework — HDP delegation provenance middleware for Microsoft agent-framework."""

from ._types import HdpPrincipal
from .middleware import HDPScopeViolationError, HdpMiddleware, ScopePolicy
from .verify import verify_chain

__all__ = [
    "HdpMiddleware",
    "HdpPrincipal",
    "HDPScopeViolationError",
    "ScopePolicy",
    "verify_chain",
]
