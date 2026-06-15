"""Vulnerable timeline: revoke-after-issue, tool call still passes, no detection.

Run:  python -m vulnerable.demo
"""

from __future__ import annotations

from .client import McpAgentClient
from .oauth import AuthorizationServer
from .server import StatelessMcpServer

T0 = 1_900_000_000           # arbitrary epoch seconds
REVOKE_AT = T0 + 300         # authority pulled 5 minutes after issuance
CALL_AT = T0 + 600           # agent acts 10 minutes after issuance
TOKEN_TTL = 3600             # 1 hour


def run() -> dict:
    AGENT_SUB = "agent:crm-assistant"
    AUD = "mcp://crm-server"

    as_ = AuthorizationServer()
    as_.grant_authority(AGENT_SUB, {"crm:read", "crm:delete"})
    token = as_.issue_token(AGENT_SUB, AUD, "crm:read crm:delete", TOKEN_TTL, now=T0)
    jti = token.split(".")[1]  # only for narration; introspection uses claims

    server = StatelessMcpServer(as_public_pem=as_.public_pem, audience=AUD)
    client = McpAgentClient(server=server, bearer_token=token)

    # Authority revoked at the AS, after the token was issued.
    as_.revoke_authority(AGENT_SUB)

    # What introspection WOULD say now (the call the stateless server skips):
    issued_jti = next(iter(as_._issued))
    introspection = as_.introspect(issued_jti)  # {"active": False}

    # The agent acts. The stateless server validates the token locally and
    # executes -- with no idea the grant was pulled.
    result = client.delete_contact("c-1001", now=CALL_AT)

    return {
        "token_issued": True,
        "introspection_would_say_active": introspection["active"],   # False
        "delete_result": result,                                     # deleted: True
        "deleted_with_revoked_authority": result["deleted"],         # True == the gap
        "detected": False,
        "server_audit_log": server.audit_log,
        "remaining_contacts": list(server.contacts),
    }


def main() -> None:
    r = run()
    print("=" * 70)
    print("VULNERABLE PATH  -- stateless OAuth 2.1 bearer (2026-07-28 profile)")
    print("=" * 70)
    print(f"  token issued at T0, ttl {TOKEN_TTL}s")
    print(f"  authority REVOKED at the AS at T0+{REVOKE_AT - T0}s")
    print(f"  AS introspection at call time would report active = "
          f"{r['introspection_would_say_active']}  (server never asks)")
    print(f"  agent calls delete_contact at T0+{CALL_AT - T0}s")
    print(f"  -> server validated token statelessly and EXECUTED: {r['delete_result']}")
    print(f"  -> effect happened on revoked authority: {r['deleted_with_revoked_authority']}")
    print(f"  -> detected by the server: {r['detected']}")
    print()
    print("  The token passed (signature + aud + exp + scope all valid), then the")
    print("  agent acted. Revocation never reached the request path. PASSES, THEN ACTS.")


if __name__ == "__main__":
    main()
