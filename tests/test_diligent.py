"""The diligent baseline CLOSES the revoke-after-issue gap (introspection +
short TTL), but still lacks four properties the PFC governed path provides.
See diligent/LIMITS.md."""

import pytest

from diligent.demo import run
from diligent.oauth import AuthorizationServer, TokenInvalid
from diligent.server import DiligentMcpServer

AUD = "mcp://crm-server"
SUB = "agent:crm-assistant"
T0 = 1_900_000_000


def _allowed_call():
    """A fresh AS + server where one delete is legitimately allowed."""
    as_ = AuthorizationServer()
    as_.grant_authority(SUB, {"crm:read", "crm:delete"})
    token = as_.issue_token(SUB, AUD, "crm:read crm:delete", 900, now=T0)
    server = DiligentMcpServer(as_public_pem=as_.public_pem, introspect=as_.introspect, audience=AUD)
    result = server.call_tool("manage_crm_objects", "delete", {"contactId": "c-1002"}, token, now=T0 + 10)
    return as_, server, token, result


# --------------------------------------------------------------------------
# It DOES close the revoke-after-issue gap.
# --------------------------------------------------------------------------


def test_introspection_closes_revoke_after_issue_gap():
    r = run()
    assert r["gap_closed"] is True
    assert r["contact_survived"] is True
    assert r["server_audit_log"] == []          # nothing executed


# --------------------------------------------------------------------------
# Limit 1: no signed, action-bound attestation.
# --------------------------------------------------------------------------


def test_no_signed_action_bound_attestation():
    _, server, _, result = _allowed_call()
    assert result["deleted"] is True
    # The result is a plain dict: no signature, no payload binding.
    assert "signature" not in result
    assert "payloadHash" not in result
    # The only record is an unsigned audit line that does not bind the payload.
    entry = server.audit_log[0]
    assert "signature" not in entry
    assert "payloadHash" not in entry


# --------------------------------------------------------------------------
# Limit 2: no per-action-class freshness object.
# --------------------------------------------------------------------------


def test_no_per_action_class_freshness_object():
    as_, server, token, _ = _allowed_call()
    # The server has no concept of per-action freshness bounds.
    assert not hasattr(server, "freshness_bounds")
    # Introspection is binary and carries no staleness bound / capture time.
    info = as_.introspect("jti-1")            # the first issued token's jti
    for absent in ("freshnessBound", "maxAge", "maxAgeMs", "capturedAt", "riskClass"):
        assert absent not in info
    # And the decision record carries no freshness object either.
    assert "freshnessBound" not in server.audit_log[0]


# --------------------------------------------------------------------------
# Limit 3: no trustless re-derivation.
# --------------------------------------------------------------------------


def test_no_trustless_re_derivation():
    _, server, _, _ = _allowed_call()
    # The only evidence is the server's OWN audit log, and it is unsigned:
    # verifying the decision requires trusting the server.
    assert all("signature" not in e for e in server.audit_log)
    # The server publishes no verification key and no portable, replayable
    # artifact a third party could independently re-derive the verdict from.
    assert not hasattr(server, "public_pem")
    assert not hasattr(server, "verify")


# --------------------------------------------------------------------------
# Limit 4: no defense against silent scope expansion.
# --------------------------------------------------------------------------


def test_silent_scope_expansion_is_undetected():
    as_ = AuthorizationServer()
    as_.grant_authority(SUB, {"crm:read"})                       # human approved READ ONLY
    read_token = as_.issue_token(SUB, AUD, "crm:read", 900, now=T0)
    server = DiligentMcpServer(as_public_pem=as_.public_pem, introspect=as_.introspect, audience=AUD)

    # With read-only authority, a delete is correctly refused.
    with pytest.raises(TokenInvalid):
        server.call_tool("manage_crm_objects", "delete", {"contactId": "c-1002"}, read_token, now=T0 + 10)

    # SILENT EXPANSION: the grant is broadened and a token refreshed, with NO
    # fresh human-in-the-loop authorization ceremony.
    as_.grant_authority(SUB, {"crm:read", "crm:delete"})
    refreshed = as_.issue_token(SUB, AUD, "crm:read crm:delete", 900, now=T0 + 20)

    # The diligent server honors the now-broader live scope and deletes.
    result = server.call_tool("manage_crm_objects", "delete", {"contactId": "c-1002"}, refreshed, now=T0 + 30)
    assert result["deleted"] is True
    # The server keeps NO immutable record of what a human originally authorized,
    # so it cannot detect that authority was widened without a new ceremony.
    assert not hasattr(server, "human_grant")
