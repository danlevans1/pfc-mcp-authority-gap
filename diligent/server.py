"""A diligent stateless MCP resource server.

Same stateless bearer validation as ``vulnerable/`` (signature + audience +
expiry), PLUS an RFC 7662 introspection round-trip on every effectful call. It
authorizes against the **live** introspection scope, so a revoked grant is
caught promptly rather than at token expiry. Short token TTLs further bound
exposure.

This is a faithful, reasonable design — not a strawman. Its limits are
structural, not a matter of being careless; see LIMITS.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .oauth import TokenInvalid, verify_jwt_stateless

TOOL_SCOPES = {
    "manage_crm_objects.delete": "crm:delete",
    "manage_crm_objects.read": "crm:read",
}


@dataclass
class DiligentMcpServer:
    as_public_pem: str
    introspect: Callable[[str], dict]          # RFC 7662 introspection endpoint
    audience: str = "mcp://crm-server"
    contacts: dict[str, dict] = field(default_factory=lambda: {
        "c-1001": {"name": "Acme Corp", "owner": "rep-7"},
        "c-1002": {"name": "Globex", "owner": "rep-7"},
    })
    audit_log: list[dict] = field(default_factory=list)

    def call_tool(self, tool: str, operation: str, arguments: dict,
                  bearer_token: str, now: int) -> dict:
        action = f"{tool}.{operation}"
        # 1) stateless validation (sig + aud + exp)
        claims = verify_jwt_stateless(bearer_token, self.as_public_pem, self.audience, now=now)
        # 2) DILIGENCE: live introspection before any effect
        info = self.introspect(claims["jti"])
        if not info.get("active"):
            raise TokenInvalid("introspection: token/grant is inactive (revoked)")
        required = TOOL_SCOPES.get(action)
        if required is None:
            raise TokenInvalid(f"unknown tool {action}")
        # 3) authorize against the LIVE introspection scope
        if required not in info["scope"].split():
            raise TokenInvalid("insufficient live scope")

        result = self._dispatch(action, arguments)
        # The only record is this server's own, UNSIGNED audit line.
        self.audit_log.append({
            "action": action, "sub": info["sub"], "jti": claims["jti"],
            "at": now, "introspected": True,
        })
        return result

    def _dispatch(self, action: str, arguments: dict) -> dict:
        if action == "manage_crm_objects.delete":
            cid = arguments["contactId"]
            removed = self.contacts.pop(cid, None)
            return {"deleted": removed is not None, "contactId": cid}
        if action == "manage_crm_objects.read":
            cid = arguments["contactId"]
            return {"contact": self.contacts.get(cid)}
        raise TokenInvalid(f"unknown action {action}")
