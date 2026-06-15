"""A stock, stateless MCP resource server (2026-07-28 profile).

It exposes one CRM tool. Authorization is OAuth 2.1 bearer: on every call it
validates the access token *statelessly* -- signature, audience, expiry, and
the scope claim -- and nothing else. It never calls introspection and never
consults a revocation list. This is a faithful "happy path" implementation, not
a strawman: it is exactly what the stateless profile asks for.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .oauth import TokenInvalid, verify_jwt_stateless

# scope required to invoke each tool
TOOL_SCOPES = {
    "manage_crm_objects.delete": "crm:delete",
    "manage_crm_objects.read": "crm:read",
}


@dataclass
class StatelessMcpServer:
    as_public_pem: str
    audience: str = "mcp://crm-server"
    # in-memory CRM the tools mutate
    contacts: dict[str, dict] = field(default_factory=lambda: {
        "c-1001": {"name": "Acme Corp", "owner": "rep-7"},
        "c-1002": {"name": "Globex", "owner": "rep-7"},
    })
    audit_log: list[dict] = field(default_factory=list)

    def call_tool(self, tool: str, operation: str, arguments: dict,
                  bearer_token: str, now: int) -> dict:
        action = f"{tool}.{operation}"
        # ---- stateless bearer validation: this is the WHOLE auth check ----
        claims = verify_jwt_stateless(bearer_token, self.as_public_pem, self.audience, now=now)
        required = TOOL_SCOPES.get(action)
        if required is None:
            raise TokenInvalid(f"unknown tool {action}")
        if required not in claims["scope"].split():
            raise TokenInvalid("insufficient scope")
        # NOTE: no introspection, no revocation check. The server cannot know
        # the grant behind this token was pulled five minutes ago.

        # ---- execute the effect ------------------------------------------
        result = self._dispatch(action, arguments)
        self.audit_log.append({"action": action, "sub": claims["sub"], "jti": claims["jti"], "at": now})
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
