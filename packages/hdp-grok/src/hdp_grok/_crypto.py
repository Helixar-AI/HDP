"""Cryptographic primitives for hdp-grok — Ed25519 + RFC 8785.

Low-level helpers (_b64url, _canonicalize, sign_root, sign_hop, verify_root,
verify_hop) are copied verbatim from hdp-crewai/_crypto.py and share the same
wire format.

High-level functions (issue_root_token, extend_token_chain,
verify_token_with_key) are the public contract for HdpMiddleware.
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
import uuid
from typing import Any
from uuid import UUID

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# ── Low-level helpers (wire-format compatible with hdp-crewai) ────────────────

def _b64url(sig_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def _canonicalize(obj: Any) -> bytes:
    return jcs.canonicalize(obj)


def _sign_root(unsigned_token: dict, private_key_bytes: bytes, kid: str) -> dict:
    payload = {f: unsigned_token[f] for f in ["hdp", "header", "principal", "scope"]}
    payload["chain"] = []
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = key.sign(message)
    return {
        "alg": "Ed25519",
        "kid": kid,
        "value": _b64url(sig_bytes),
    }


def _sign_hop(cumulative_chain: list[dict], root_sig_value: str, private_key_bytes: bytes) -> str:
    payload = [root_sig_value, *cumulative_chain]
    message = _canonicalize(payload)
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return _b64url(key.sign(message))


def _verify_root(token: dict, public_key: Ed25519PublicKey) -> bool:
    try:
        if token["signature"].get("alg") != "Ed25519":
            return False
        payload = {f: token[f] for f in ["hdp", "header", "principal", "scope"]}
        payload["chain"] = []
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(token["signature"]["value"])
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


def _verify_hop(
    cumulative_chain: list[dict],
    root_sig_value: str,
    hop_signature: str,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        payload = [root_sig_value, *cumulative_chain]
        message = _canonicalize(payload)
        sig_bytes = _b64url_decode(hop_signature)
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


# ── High-level functions used by HdpMiddleware ────────────────────────────────

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_PRINCIPAL_ID_TYPES = {"opaque", "email", "uuid", "did", "poh"}
_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member {key!r}")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


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


def _invalid_json_result(message: str) -> dict:
    return {"valid": False, "hop_count": 0, "principal_id": None,
            "session_id": None, "expires_at": 0, "expired": False,
            "recorded_after_period": [],
            "integrity_violations": [f"Step 0: Input validation failed: {message}"],
            "violations": ["invalid JSON"], "chain": []}


def _validate_token_input(token: object) -> str | None:
    if not isinstance(token, dict):
        return "token must be an object"
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
        return "token.header must be an object"
    signature = token.get("signature")
    if not isinstance(signature, dict):
        return "token.signature must be an object"
    for field_name in ("alg", "kid", "value"):
        if not isinstance(signature.get(field_name), str):
            return f"signature.{field_name} must be a string"
    if not signature["kid"]:
        return "signature.kid must not be empty"
    if re.fullmatch(r"[A-Za-z0-9_-]{86}", signature["value"]) is None:
        return "signature.value must be an 86-character base64url string"
    if "signed_fields" in signature and (
        signature["signed_fields"] != ["header", "principal", "scope"]
    ):
        return "signature.signed_fields must be [header, principal, scope]"
    if not isinstance(principal, dict):
        return "token.principal must be an object"
    if not isinstance(scope, dict):
        return "token.scope must be an object"
    if not isinstance(chain, list) or any(not isinstance(hop, dict) for hop in chain):
        return "token.chain must be a list of objects"

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
    if not isinstance(header.get("session_id"), str) or not header["session_id"]:
        return "header.session_id must be a non-empty string"
    if not isinstance(header.get("version"), str):
        return "header.version must be a string"
    if "parent_token_id" in header:
        parent_token_id = header["parent_token_id"]
        if not isinstance(parent_token_id, str):
            return "header.parent_token_id must be a UUID string"
        try:
            parsed_parent_token_id = UUID(parent_token_id)
        except ValueError:
            return "header.parent_token_id must be a UUID string"
        if str(parsed_parent_token_id) != parent_token_id.lower():
            return "header.parent_token_id must be a UUID string"

    if not isinstance(principal.get("id"), str):
        return "principal.id must be a string"
    id_type = principal.get("id_type")
    if not isinstance(id_type, str) or (
        id_type not in _PRINCIPAL_ID_TYPES
        and re.fullmatch(r"x-[^\r\n\u2028\u2029]+", id_type) is None
    ):
        return "principal.id_type must be a defined value or match 'x-...'"
    for field_name in ("poh_credential", "display_name"):
        if field_name in principal and not isinstance(principal[field_name], str):
            return f"principal.{field_name} must be a string"
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

    if "constraints" in scope and not isinstance(scope["constraints"], list):
        return "scope.constraints must be an array"
    if "extensions" in scope and not isinstance(scope["extensions"], dict):
        return "scope.extensions must be an object"

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
        hop_signature = hop.get("hop_signature")
        if not isinstance(hop_signature, str) or re.fullmatch(
            r"[A-Za-z0-9_-]{86}", hop_signature
        ) is None:
            return f"chain[{index}].hop_signature must be an 86-character base64url string"
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

def issue_root_token(
    signing_key: bytes,
    key_id: str,
    session_id: str,
    principal_id: str,
    scope: list[str],
    expires_in: int,
    max_hops: int | None = None,
) -> dict:
    """Build and sign a root HDP token dict."""
    if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in <= 0:
        raise ValueError("expires_in must be a positive integer")
    now = int(time.time() * 1000)
    scope_record: dict = {
        "intent": principal_id,
        "data_classification": "internal",
        "network_egress": True,
        "persistence": False,
        "authorized_tools": scope,
    }
    if max_hops is not None:
        scope_record["max_hops"] = max_hops
    unsigned: dict = {
        "hdp": "0.1",
        "header": {
            "token_id": str(uuid.uuid4()),
            "issued_at": now,
            "expires_at": now + expires_in * 1000,
            "session_id": session_id,
            "version": "0.1",
        },
        "principal": {
            "id": principal_id,
            "id_type": "opaque",
        },
        "scope": scope_record,
        "chain": [],
    }
    candidate = {**unsigned, "signature": {"alg": "Ed25519", "kid": key_id, "value": "A" * 86}}
    input_error = _validate_token_input(candidate)
    if input_error is not None:
        raise ValueError(input_error)
    signature = _sign_root(unsigned, signing_key, key_id)
    return {**unsigned, "signature": signature}


def extend_token_chain(
    parent_token: dict,
    signing_key: bytes,
    key_id: str,
    delegatee_id: str,
    additional_scope: list[str],
) -> dict:
    """Append a signed hop to parent_token and return the updated dict."""
    input_error = _validate_token_input(parent_token)
    if input_error is not None:
        raise ValueError(input_error)
    current_chain: list = parent_token.get("chain", [])
    max_hops = parent_token.get("scope", {}).get("max_hops")
    if max_hops is not None and len(current_chain) >= max_hops:
        return parent_token

    hop_seq = len(current_chain) + 1
    timestamp = int(time.time() * 1000)
    if current_chain:
        timestamp = max(timestamp, current_chain[-1]["timestamp"])
    unsigned_hop: dict = {
        "seq": hop_seq,
        "agent_id": delegatee_id,
        "agent_type": "sub-agent",
        "timestamp": timestamp,
        "action_summary": "",
        "parent_hop": hop_seq - 1,
    }
    candidate = {
        **parent_token,
        "chain": [*current_chain, {**unsigned_hop, "hop_signature": "A" * 86}],
    }
    input_error = _validate_token_input(candidate)
    if input_error is not None:
        raise ValueError(input_error)
    cumulative = [*current_chain, unsigned_hop]
    hop_sig = _sign_hop(cumulative, parent_token["signature"]["value"], signing_key)
    signed_hop = {**unsigned_hop, "hop_signature": hop_sig}
    return {**parent_token, "chain": [*current_chain, signed_hop]}


def verify_token_with_key(token_str: str, public_key_bytes: bytes) -> dict:
    """Verify serialized token input with duplicate-member detection."""
    try:
        token = json.loads(
            token_str,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_non_finite_number,
        )
    except json.JSONDecodeError:
        return _invalid_json_result("invalid JSON")
    except ValueError as exc:
        return _invalid_json_result(str(exc))

    if not isinstance(token, dict):
        return {"valid": False, "hop_count": 0, "principal_id": None,
                "session_id": None, "expires_at": 0, "expired": False,
                "recorded_after_period": [],
                "integrity_violations": ["Step 0: Input validation failed: token must be an object"],
                "violations": [], "chain": []}

    input_error = _validate_token_input(token)
    if input_error:
        header = token.get("header")
        principal = token.get("principal")
        chain = token.get("chain")
        return {"valid": False, "hop_count": len(chain) if isinstance(chain, list) else 0,
                "principal_id": principal.get("id") if isinstance(principal, dict) else None,
                "session_id": header.get("session_id") if isinstance(header, dict) else None,
                "expires_at": header.get("expires_at", 0) if isinstance(header, dict) else 0,
                "expired": False, "recorded_after_period": [],
                "integrity_violations": [f"Step 0: Input validation failed: {input_error}"],
                "violations": [], "chain": chain if isinstance(chain, list) else []}

    header = token["header"]
    scope = token["scope"]
    chain = token["chain"]

    pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    now_ms = int(time.time() * 1000)
    expires_at: int = header["expires_at"]
    expired = now_ms > expires_at
    recorded_after_period = [
        hop["seq"]
        for hop in chain
        if isinstance(hop.get("seq"), int)
        and not isinstance(hop.get("seq"), bool)
        and isinstance(hop.get("timestamp"), int)
        and not isinstance(hop.get("timestamp"), bool)
        and hop["timestamp"] >= expires_at
    ]
    extensions = scope.get("extensions")
    scope_violations = extensions.get("scope_violations", []) if isinstance(extensions, dict) else []
    if not isinstance(scope_violations, list):
        scope_violations = []
    integrity_violations: list[str] = []

    def result(valid: bool) -> dict:
        return {
            "valid": valid,
            "hop_count": len(chain),
            "principal_id": token.get("principal", {}).get("id")
            if isinstance(token.get("principal"), dict) else None,
            "session_id": header.get("session_id"),
            "expires_at": expires_at,
            "expired": expired,
            "recorded_after_period": recorded_after_period,
            "integrity_violations": integrity_violations,
            "violations": scope_violations,
            "chain": chain,
        }

    # Step 1: protocol and header versions.
    version = token.get("hdp")
    if version != "0.1":
        integrity_violations.append(f"Step 1: unsupported HDP version {version!r}")
        return result(False)
    if header.get("version") != version:
        integrity_violations.append("Step 1: header.version does not match hdp")
        return result(False)

    # Step 2: root signature.
    if not _verify_root(token, pub_key):
        integrity_violations.append("Step 2: Root signature invalid")
        return result(False)

    # Step 3: sequence, parent references, and monotonic hop timestamps.
    previous_timestamp: int | None = None
    for index, hop in enumerate(chain):
        expected_seq = index + 1
        if hop.get("seq") != expected_seq:
            integrity_violations.append(
                f"Step 3: non-sequential seq at position {index}: "
                f"expected {expected_seq}, got {hop.get('seq')!r}"
            )
            return result(False)

        parent_hop = hop.get("parent_hop")
        if (
            not isinstance(parent_hop, int)
            or isinstance(parent_hop, bool)
            or parent_hop < 0
            or parent_hop >= expected_seq
        ):
            integrity_violations.append(f"Step 3: invalid parent_hop at hop {expected_seq}")
            return result(False)

        timestamp = hop.get("timestamp")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            integrity_violations.append(f"Step 3: invalid timestamp at hop {expected_seq}")
            return result(False)
        if previous_timestamp is not None and timestamp < previous_timestamp:
            integrity_violations.append(f"Step 3: timestamp decreases at hop {expected_seq}")
            return result(False)
        previous_timestamp = timestamp

    # Step 4: cumulative hop signatures.
    root_sig_value = token.get("signature", {}).get("value", "")
    for index, hop in enumerate(chain):
        hop_sig = hop.get("hop_signature")
        if not isinstance(hop_sig, str) or not hop_sig:
            integrity_violations.append(f"Step 4: hop {index + 1} has no hop_signature")
            return result(False)
        unsigned_current = {key: value for key, value in hop.items() if key != "hop_signature"}
        cumulative = [*chain[:index], unsigned_current]
        if not _verify_hop(cumulative, root_sig_value, hop_sig, pub_key):
            integrity_violations.append(f"Step 4: hop {index + 1} signature invalid")
            return result(False)

    # Step 5: recorded depth.
    max_hops = scope.get("max_hops")
    if max_hops is not None and len(chain) > max_hops:
        integrity_violations.append(
            f"Step 5: chain depth {len(chain)} exceeds max_hops {max_hops}"
        )
        return result(False)

    return result(True)
