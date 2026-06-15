"""Diligent timeline: introspection + short TTL closes the revoke-after-issue
gap that the vulnerable path leaves open.

Run:  python -m diligent.demo
"""

from __future__ import annotations

from .oauth import AuthorizationServer, TokenInvalid
from .server import DiligentMcpServer

T0 = 1_900_000_000
REVOKE_AT = T0 + 300         # authority pulled 5 minutes after issuance
CALL_AT = T0 + 600           # agent acts 10 minutes after issuance
TOKEN_TTL = 900              # 15 minutes (was 1 hour in vulnerable/)


def run() -> dict:
    AGENT_SUB = "agent:crm-assistant"
    AUD = "mcp://crm-server"

    as_ = AuthorizationServer()
    as_.grant_authority(AGENT_SUB, {"crm:read", "crm:delete"})
    token = as_.issue_token(AGENT_SUB, AUD, "crm:read crm:delete", TOKEN_TTL, now=T0)

    server = DiligentMcpServer(as_public_pem=as_.public_pem, introspect=as_.introspect, audience=AUD)

    # Authority revoked at the AS after issuance.
    as_.revoke_authority(AGENT_SUB)

    # The agent acts. This time the server introspects before the effect.
    denied = False
    result = None
    try:
        result = server.call_tool("manage_crm_objects", "delete", {"contactId": "c-1001"},
                                  token, now=CALL_AT)
    except TokenInvalid as exc:
        denied = True
        reason = str(exc)

    return {
        "gap_closed": denied,
        "denied_reason": reason if denied else None,
        "delete_result": result,
        "contact_survived": "c-1001" in server.contacts,
        "server_audit_log": server.audit_log,   # empty: nothing executed
    }


def main() -> None:
    r = run()
    print("=" * 70)
    print("DILIGENT PATH  -- stateless OAuth + RFC 7662 introspection + 15m TTL")
    print("=" * 70)
    print(f"  token issued at T0, ttl {TOKEN_TTL}s (15 min)")
    print(f"  authority REVOKED at the AS at T0+{REVOKE_AT - T0}s")
    print(f"  agent calls delete_contact at T0+{CALL_AT - T0}s")
    print(f"  -> server introspected first and DENIED: {r['gap_closed']}")
    print(f"     reason: {r['denied_reason']}")
    print(f"  -> contact survived: {r['contact_survived']}")
    print()
    print("  The revoke-after-issue gap is CLOSED. But see diligent/LIMITS.md for")
    print("  what this still cannot do that the PFC governed path can:")
    print("   - no signed, action-bound attestation of the decision;")
    print("   - no per-action-class freshness object (introspection is binary,")
    print("     with no declared staleness bound on cached answers);")
    print("   - no trustless re-derivation (only this server's unsigned audit log);")
    print("   - no defense against silent scope expansion past an immutable human grant.")


if __name__ == "__main__":
    main()
