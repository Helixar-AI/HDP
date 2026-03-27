"""Python types mirroring the HDP TypeScript SDK schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

DataClassification = Literal["public", "internal", "confidential", "restricted"]
AgentType = Literal["orchestrator", "sub-agent", "tool-executor", "custom"]
PrincipalIdType = Literal["email", "uuid", "did", "poh", "opaque"]


@dataclass
class HdpHeader:
    token_id: str
    issued_at: int
    expires_at: int
    session_id: str
    version: str = "0.1"
    parent_token_id: Optional[str] = None


@dataclass
class HdpPrincipal:
    id: str
    id_type: PrincipalIdType
    display_name: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class HdpScope:
    intent: str
    data_classification: DataClassification
    network_egress: bool
    persistence: bool
    authorized_tools: Optional[list[str]] = None
    authorized_resources: Optional[list[str]] = None
    max_hops: Optional[int] = None


@dataclass
class HdpSignature:
    alg: str
    kid: str
    value: str
    signed_fields: list[str] = field(default_factory=lambda: ["header", "principal", "scope"])


@dataclass
class HopRecord:
    seq: int
    agent_id: str
    agent_type: AgentType
    timestamp: int
    action_summary: str
    parent_hop: int
    hop_signature: str
    agent_fingerprint: Optional[str] = None


@dataclass
class HdpToken:
    hdp: str
    header: HdpHeader
    principal: HdpPrincipal
    scope: HdpScope
    chain: list[HopRecord]
    signature: HdpSignature
