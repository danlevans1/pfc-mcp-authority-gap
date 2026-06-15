"""The vulnerable path PASSES, THEN ACTS: a stateless OAuth 2.1 bearer token
whose underlying authority was revoked after issuance still authorizes a tool
call, and the effect happens with no detection."""

from vulnerable.demo import run
from vulnerable.oauth import (
    AuthorizationServer,
    TokenExpired,
    TokenInvalid,
    verify_jwt_stateless,
)

AUD = "mcp://crm-server"


def test_revoked_authority_still_executes_with_no_detection():
    r = run()
    # The grant behind the token was pulled before the call...
    assert r["introspection_would_say_active"] is False
    # ...yet the stateless server validated and executed the delete.
    assert r["delete_result"]["deleted"] is True
    assert r["deleted_with_revoked_authority"] is True
    # The server has no notion that anything was wrong.
    assert r["detected"] is False
    assert "c-1001" not in r["remaining_contacts"]
    # The effect is recorded as a normal, "successful" tool call.
    assert len(r["server_audit_log"]) == 1


def test_stateless_validation_only_checks_sig_aud_exp_scope():
    """The token itself remains cryptographically valid post-revocation: that
    is precisely why stateless validation cannot stop it."""
    as_ = AuthorizationServer()
    as_.grant_authority("agent:x", {"crm:delete"})
    token = as_.issue_token("agent:x", AUD, "crm:delete", 3600, now=1000)
    as_.revoke_authority("agent:x")
    # Stateless validation passes after revocation (no introspection here).
    claims = verify_jwt_stateless(token, as_.public_pem, AUD, now=2000)
    assert claims["sub"] == "agent:x"
    # Only expiry stops it -- eventually, not promptly.
    try:
        verify_jwt_stateless(token, as_.public_pem, AUD, now=1000 + 3601)
        assert False, "expected expiry"
    except TokenExpired:
        pass


def test_wrong_audience_or_signature_is_rejected():
    """Sanity: the baseline is a faithful validator, not a strawman."""
    as_ = AuthorizationServer()
    as_.grant_authority("agent:x", {"crm:delete"})
    token = as_.issue_token("agent:x", AUD, "crm:delete", 3600, now=1000)
    try:
        verify_jwt_stateless(token, as_.public_pem, "mcp://other", now=1500)
        assert False
    except TokenInvalid:
        pass
    other = AuthorizationServer()
    try:
        verify_jwt_stateless(token, other.public_pem, AUD, now=1500)
        assert False
    except TokenInvalid:
        pass
