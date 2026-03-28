"""Slim HDP types for hdp-grok — no framework dependencies."""
from __future__ import annotations

from typing import Literal, Optional

DataClassification = Literal["public", "internal", "confidential", "restricted"]
AgentType = Literal["orchestrator", "sub-agent", "tool-executor", "custom"]
PrincipalIdType = Literal["email", "uuid", "did", "poh", "opaque"]
