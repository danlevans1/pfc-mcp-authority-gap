"""A stock MCP client / agent.

It obtains a bearer token once and reuses it for tool calls -- the normal MCP
client pattern. The client holds the credential directly (no mediator), which
is exactly why a revocation after issuance cannot be enforced before exp.
"""

from __future__ import annotations

from dataclasses import dataclass

from .server import StatelessMcpServer


@dataclass
class McpAgentClient:
    server: StatelessMcpServer
    bearer_token: str

    def delete_contact(self, contact_id: str, now: int) -> dict:
        return self.server.call_tool(
            "manage_crm_objects", "delete", {"contactId": contact_id},
            self.bearer_token, now=now,
        )

    def read_contact(self, contact_id: str, now: int) -> dict:
        return self.server.call_tool(
            "manage_crm_objects", "read", {"contactId": contact_id},
            self.bearer_token, now=now,
        )
