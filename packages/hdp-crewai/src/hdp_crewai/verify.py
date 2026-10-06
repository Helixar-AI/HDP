"""Offline, time-independent verification for HDP records."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._crypto import verify_hop, verify_root

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_PRINCIPAL_ID_TYPES = {"opaque", "email", "uuid", "did", "poh"}
_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}


def _validate_json_value(value: object, path: str = "token") -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            if math.isfinite(float(value)) and int(float(value)) == value:
                return None
        except (OverflowError, ValueError):
            pass
        return f"{path} integer must be exactly representable as an IEEE 754 number"
    if isinstance(value, float):
        return None if math.isfinite(value) else f"{path} must not contain non-finite numbers"
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return f"{path} contains invalid Unicode"
        return None
    if isinstance(value, list):
        for index, item in enumerate(value):
            error = _validate_json_value(item, f"{path}[{index}]")
            if error:
                return error
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return f"{path} object keys must be strings"
            error = _validate_json_value(key, f"{path} key")
            if error:
                return error
            error = _validate_json_value(item, f"{path}.{key}")
            if error:
                return error
        return None
    return f"{path} contains a value that is not JSON"


def _object_from_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member {key!r}")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _parse_token_input(token: object) -> tuple[object, str | None]:
    if not isinstance(token, str):
        return token, None
    try:
        return json.loads(
            token,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_non_finite_number,
        ), None
    except ValueError as exc:
        return None, str(exc)


def _validate_token_input(token: object) -> str | None:
    if not isinstance(token, dict):
        return "token must be a dictionary"
    json_error = _validate_json_value(token)
    if json_error:
        return json_error
    if set(token) != {"hdp", "header", "principal", "scope", "chain", "signature"}:
        return "token must contain exactly the six defined top-level fields"
    if not isinstance(token.get("hdp"), str):
        return "token.hdp must be a string"

    header = token.get("header")
    principal = token.get("principal")
    scope = token.get("scope")
    chain = token.get("chain")
    if not isinstance(header, dict):
        return "token.header must be a dictionary"
    if not isinstance(token.get("signature"), dict):
        return "token.signature must be a dictionary"
    if not isinstance(principal, dict):
        return "token.principal must be a dictionary"
    if not isinstance(scope, dict):
        return "token.scope must be a dictionary"
    if not isinstance(chain, list) or any(not isinstance(hop, dict) for hop in chain):
        return "token.chain must be a list of dictionaries"

    token_id = header.get("token_id")
    if not isinstance(token_id, str):
        return "header.token_id must be a version 4 UUID"
    try:
        parsed_token_id = UUID(token_id)
    except ValueError:
        return "header.token_id must be a version 4 UUID"
    if parsed_token_id.version != 4 or str(parsed_token_id) != token_id.lower():
        return "header.token_id must be a version 4 UUID"

    for field_name in ("issued_at", "expires_at"):
        value = header.get(field_name)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value > _MAX_SAFE_INTEGER
        ):
            return f"header.{field_name} must be an integer from 0 to {_MAX_SAFE_INTEGER}"
    if header["expires_at"] <= header["issued_at"]:
        return "header.expires_at must be greater than header.issued_at"
    if not isinstance(header.get("session_id"), str):
        return "header.session_id must be a string"
    if not isinstance(header.get("version"), str):
        return "header.version must be a string"
    if "parent_token_id" in header and not isinstance(header["parent_token_id"], str):
        return "header.parent_token_id must be a string"

    if not isinstance(principal.get("id"), str):
        return "principal.id must be a string"
    id_type = principal.get("id_type")
    if not isinstance(id_type, str) or (
        id_type not in _PRINCIPAL_ID_TYPES and not id_type.startswith("x-")
    ):
        return "principal.id_type must be a defined value or start with 'x-'"
    if "metadata" in principal and not isinstance(principal["metadata"], dict):
        return "principal.metadata must be an object"

    if not isinstance(scope.get("intent"), str):
        return "scope.intent must be a string"
    for field_name in ("authorized_tools", "authorized_resources"):
        values = scope.get(field_name)
        if field_name in scope and (
            not isinstance(values, list) or any(not isinstance(value, str) for value in values)
        ):
            return f"scope.{field_name} must be a list of strings"
    classification = scope.get("data_classification")
    if not isinstance(classification, str) or classification not in _DATA_CLASSIFICATIONS:
        return "scope.data_classification must be a defined classification"
    for field_name in ("network_egress", "persistence"):
        if not isinstance(scope.get(field_name), bool):
            return f"scope.{field_name} must be a boolean"
    if "max_hops" in scope:
        max_hops = scope["max_hops"]
        if (
            not isinstance(max_hops, int)
            or isinstance(max_hops, bool)
            or max_hops < 1
            or max_hops > _MAX_SAFE_INTEGER
        ):
            return f"scope.max_hops must be a positive integer up to {_MAX_SAFE_INTEGER}"

    for index, hop in enumerate(chain):
        seq = hop.get("seq")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or seq < 1
            or seq > _MAX_SAFE_INTEGER
        ):
            return f"chain[{index}].seq must be a positive integer up to {_MAX_SAFE_INTEGER}"
        for field_name in ("agent_id", "agent_type", "action_summary"):
            if not isinstance(hop.get(field_name), str):
                return f"chain[{index}].{field_name} must be a string"
        if "agent_fingerprint" in hop and not isinstance(hop["agent_fingerprint"], str):
            return f"chain[{index}].agent_fingerprint must be a string"
        for field_name in ("timestamp", "parent_hop"):
            value = hop.get(field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > _MAX_SAFE_INTEGER
            ):
                return f"chain[{index}].{field_name} must be an integer from 0 to {_MAX_SAFE_INTEGER}"

    return None


@dataclass
class HopVerification:
    """Per-hop signature verification outcome."""

    seq: int
    agent_id: str
    valid: bool
    reason: str = ""


@dataclass
class VerificationResult:
    """Integrity result and separate recording-period audit result."""

    valid: bool
    token_id: str
    session_id: str
    hop_count: int
    hop_results: list[HopVerification] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    recorded_after_period: list[int] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return self.hop_count


def verify_chain(token: dict | str, public_key: Ed25519PublicKey | bytes) -> VerificationResult:
    """Verify a record without time or session state.

    String input is parsed with duplicate-member detection. For dictionary input,
    duplicate detection remains the responsibility of the caller's parser.
    """
    token, parse_error = _parse_token_input(token)
    input_error = parse_error or _validate_token_input(token)
    if input_error is not None:
        input_header = token.get("header") if isinstance(token, dict) else None
        input_chain = token.get("chain") if isinstance(token, dict) else None
        input_token_id = input_header.get("token_id") if isinstance(input_header, dict) else None
        input_session_id = input_header.get("session_id") if isinstance(input_header, dict) else None
        return VerificationResult(
            valid=False,
            token_id=input_token_id if isinstance(input_token_id, str) else "unknown",
            session_id=input_session_id if isinstance(input_session_id, str) else "unknown",
            hop_count=len(input_chain) if isinstance(input_chain, list) else 0,
            hop_results=[],
            violations=[f"Step 0: Input validation failed: {input_error}"],
            recorded_after_period=[],
        )
    header = token["header"]
    chain = token["chain"]
    scope = token["scope"]
    expires_at = header["expires_at"]
    max_hops = scope.get("max_hops")

    if isinstance(public_key, (bytes, bytearray)):
        pub = _load_raw_public_key(bytes(public_key))
    else:
        pub = public_key

    token_id = header.get("token_id", "unknown")
    session_id = header.get("session_id", "unknown")
    recorded_after_period = [
        hop["seq"]
        for hop in chain
        if isinstance(hop.get("seq"), int)
        and not isinstance(hop.get("seq"), bool)
        and isinstance(hop.get("timestamp"), int)
        and not isinstance(hop.get("timestamp"), bool)
        and hop["timestamp"] >= expires_at
    ]
    violations: list[str] = []
    hop_results: list[HopVerification] = []

    def result(valid: bool) -> VerificationResult:
        return VerificationResult(
            valid=valid,
            token_id=token_id,
            session_id=session_id,
            hop_count=len(chain),
            hop_results=hop_results,
            violations=violations,
            recorded_after_period=recorded_after_period,
        )

    # Step 1: protocol and header versions.
    version = token.get("hdp")
    if version != "0.1":
        violations.append(f"Step 1: unsupported HDP version {version!r}")
        return result(False)
    if header.get("version") != version:
        violations.append("Step 1: header.version does not match hdp")
        return result(False)

    # Step 2: root signature.
    if not verify_root(token, pub):
        violations.append("Step 2: Root signature invalid")
        return result(False)

    # Step 3: sequence, parent references, and monotonic hop timestamps.
    previous_timestamp: int | None = None
    for index, hop in enumerate(chain):
        expected_seq = index + 1
        seq = hop.get("seq")
        if seq != expected_seq:
            violations.append(
                f"Step 3: non-sequential seq at position {index}: "
                f"expected {expected_seq}, got {seq!r}"
            )
            return result(False)

        parent_hop = hop.get("parent_hop")
        if (
            not isinstance(parent_hop, int)
            or isinstance(parent_hop, bool)
            or parent_hop < 0
            or parent_hop >= expected_seq
        ):
            violations.append(f"Step 3: invalid parent_hop at hop {expected_seq}")
            return result(False)

        timestamp = hop.get("timestamp")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            violations.append(f"Step 3: invalid timestamp at hop {expected_seq}")
            return result(False)
        if previous_timestamp is not None and timestamp < previous_timestamp:
            violations.append(f"Step 3: timestamp decreases at hop {expected_seq}")
            return result(False)
        previous_timestamp = timestamp

    # Step 4: cumulative hop signatures.
    root_sig_value = token["signature"]["value"]
    for index, hop in enumerate(chain):
        seq = hop.get("seq", index + 1)
        agent_id = hop.get("agent_id", "unknown")
        hop_sig = hop.get("hop_signature")
        if not isinstance(hop_sig, str) or not hop_sig:
            reason = "Hop signature missing"
            hop_results.append(HopVerification(seq, agent_id, False, reason))
            violations.append(f"Step 4: hop {seq} has no hop_signature")
            return result(False)

        unsigned_hop = {key: value for key, value in hop.items() if key != "hop_signature"}
        cumulative = [*chain[:index], unsigned_hop]
        if not verify_hop(cumulative, root_sig_value, hop_sig, pub):
            reason = "Hop signature invalid"
            hop_results.append(HopVerification(seq, agent_id, False, reason))
            violations.append(f"Step 4: hop {seq} ({agent_id}) signature invalid")
            return result(False)
        hop_results.append(HopVerification(seq, agent_id, True))

    # Step 5: recorded depth.
    if max_hops is not None and len(chain) > max_hops:
        violations.append(f"Step 5: chain depth {len(chain)} exceeds max_hops {max_hops}")
        return result(False)

    return result(True)


def _load_raw_public_key(raw_bytes: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw_bytes)
