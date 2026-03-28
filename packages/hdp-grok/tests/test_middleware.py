"""Tests for HdpMiddleware."""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdp_grok.middleware import (
    HdpMiddleware,
    HdpSigningKeyError,
    HdpTokenMissingError,
    HdpTokenExpiredError,
)


def _make_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


class TestMiddlewareKeyResolution:
    def test_bytes_key_accepted(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key, principal_id="u@x.com")
        assert m.signing_key == key

    def test_base64url_str_accepted(self):
        key = _make_key()
        b64 = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
        m = HdpMiddleware(signing_key=b64, principal_id="u@x.com")
        assert m.signing_key == key

    def test_hex_str_accepted(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key.hex(), principal_id="u@x.com")
        assert m.signing_key == key

    def test_0x_hex_str_accepted(self):
        key = _make_key()
        m = HdpMiddleware(signing_key="0x" + key.hex(), principal_id="u@x.com")
        assert m.signing_key == key

    def test_env_var_accepted(self, monkeypatch):
        key = _make_key()
        b64 = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
        monkeypatch.setenv("HDP_SIGNING_KEY", b64)
        m = HdpMiddleware(principal_id="u@x.com")
        assert m.signing_key == key

    def test_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("HDP_SIGNING_KEY", raising=False)
        with pytest.raises(HdpSigningKeyError):
            HdpMiddleware(principal_id="u@x.com")

    def test_session_id_auto_generated(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key, principal_id="u@x.com")
        assert isinstance(m.session_id, str) and len(m.session_id) == 36

    def test_session_id_can_be_provided(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key, principal_id="u@x.com", session_id="my-session")
        assert m.session_id == "my-session"


class TestMiddlewareIssueToken:
    def _make(self, **kw):
        return HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", **kw)

    def test_issue_token_returns_json_string(self):
        m = self._make()
        result = m.issue_token()
        assert "token" in result
        token = json.loads(result["token"])
        assert token["header"]["session_id"] == m.session_id

    def test_issue_token_without_principal_raises(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key)
        with pytest.raises(ValueError, match="principal_id"):
            m.issue_token()

    def test_issue_token_rotation(self):
        m = self._make()
        r1 = m.issue_token()
        r2 = m.issue_token()
        t1 = json.loads(r1["token"])
        t2 = json.loads(r2["token"])
        assert t1["header"]["token_id"] != t2["header"]["token_id"]
        assert m._hop_count == 0

    def test_scope_passed_to_token(self):
        m = self._make()
        result = m.issue_token(scope=["read_email"])
        token = json.loads(result["token"])
        assert "read_email" in token["scope"]["authorized_tools"]


class TestMiddlewareExtendChain:
    def _make(self, **kw):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", **kw)
        m.issue_token()
        return m

    def test_extend_chain_increments_hop_count(self):
        m = self._make()
        m.extend_chain("agent-A")
        assert m._hop_count == 1
        m.extend_chain("agent-B")
        assert m._hop_count == 2

    def test_extend_chain_before_issue_raises(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key, principal_id="u@x.com")
        with pytest.raises(HdpTokenMissingError):
            m.extend_chain("agent-X")

    def test_extend_chain_on_expired_token_raises(self):
        key = _make_key()
        m = HdpMiddleware(signing_key=key, principal_id="u@x.com", default_expires_in=-1)
        m.issue_token()
        with pytest.raises(HdpTokenExpiredError):
            m.extend_chain("agent-X")

    def test_extend_chain_return_value(self):
        m = self._make()
        result = m.extend_chain("agent-A")
        assert "new_token" in result
        token = json.loads(result["new_token"])
        assert len(token["chain"]) == 1


class TestMiddlewareVerifyToken:
    def test_verify_fresh_token(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        r = m.issue_token()
        result = m.verify_token(r["token"])
        assert result["valid"] is True
        assert result["hop_count"] == 0
        assert result["expired"] is False

    def test_verify_token_with_hops(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        m.issue_token()
        m.extend_chain("a1")
        m.extend_chain("a2")
        token_str = json.dumps(m.export_current_token())
        result = m.verify_token(token_str)
        assert result["valid"] is True
        assert result["hop_count"] == 2

    def test_verify_tampered_token(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        r = m.issue_token()
        token = json.loads(r["token"])
        token["principal"]["id"] = "evil"
        result = m.verify_token(json.dumps(token))
        assert result["valid"] is False

    def test_verify_expired_token(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", default_expires_in=-1)
        r = m.issue_token()
        result = m.verify_token(r["token"])
        assert result["expired"] is True


class TestMiddlewareHandleToolCall:
    def _make(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        m.issue_token()
        return m

    def test_routes_issue_token(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        result = m.handle_tool_call("hdp_issue_token", {})
        assert "token" in result

    def test_routes_extend_chain_snake_case(self):
        m = self._make()
        result = m.handle_tool_call("hdp_extend_chain", {"delegatee_id": "agent-A"})
        assert "new_token" in result

    def test_routes_extend_chain_camel_case(self):
        m = self._make()
        result = m.handle_tool_call("hdp_extend_chain", {"delegateeId": "agent-A"})
        assert "new_token" in result

    def test_routes_verify_token(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        r = m.issue_token()
        result = m.handle_tool_call("hdp_verify_token", {"token": r["token"]})
        assert result["valid"] is True

    def test_unknown_tool_raises(self):
        m = self._make()
        with pytest.raises(ValueError, match="Unknown HDP tool"):
            m.handle_tool_call("hdp_unknown", {})


class TestMiddlewareReset:
    def test_reset_clears_token_and_hops(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        m.issue_token()
        m.extend_chain("a1")
        m.reset()
        assert m._current_token is None
        assert m._hop_count == 0

    def test_reset_preserves_session_and_principal(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", session_id="s1")
        m.issue_token()
        m.reset()
        assert m.session_id == "s1"
        assert m.principal_id == "u@x.com"


class TestMiddlewareInspection:
    def test_export_none_before_issue(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        assert m.export_current_token() is None

    def test_export_dict_after_issue(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com")
        m.issue_token()
        token = m.export_current_token()
        assert isinstance(token, dict)
        assert "signature" in token

    def test_repr_before_issue(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", session_id="s1")
        assert "s1" in repr(m)
        assert "hops=0" in repr(m)
        assert "valid=False" in repr(m)

    def test_repr_after_issue(self):
        m = HdpMiddleware(signing_key=_make_key(), principal_id="u@x.com", session_id="s1")
        m.issue_token()
        assert "valid=True" in repr(m)
