"""Channel and resource adapters for the governed deployment.

Both are thin and carry NO authorization logic (pfc-mediated-agent: that is the
mediator's job). The ResourceAdapter is the sole holder of the CRM credential;
the LLM and the runtime never see it. It is invoked only by the mediator and
only after a PRE_EFFECT BoundaryReceipt.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from pfc import ConnectorCall


@dataclass
class CrmResourceAdapter:
    """Holds the CRM credential. One adapter per credential domain."""

    # A stand-in for a real secret. Never exposed to the LLM or runtime.
    _credential: str = "crm-service-account-key-REDACTED"
    contacts: dict[str, dict] = field(default_factory=lambda: {
        "c-1001": {"name": "Acme Corp", "owner": "rep-7"},
        "c-1002": {"name": "Globex", "owner": "rep-7"},
    })

    call_actions: tuple[str, ...] = (
        "manage_crm_objects.delete",
        "manage_crm_objects.read",
    )

    def execute(self, call: ConnectorCall) -> dict:
        # The effectRef is an UNPREDICTABLE, server-assigned operation id minted
        # at execution time -- not derivable from the request. The attested
        # proof binds it, so a proof cannot be pre-fetched against a guessed
        # result before the effect actually happens.
        op = "op-" + uuid.uuid4().hex
        if call.action == "manage_crm_objects.delete":
            cid = call.payload["contactId"]
            removed = self.contacts.pop(cid, None)
            if removed is None:
                raise KeyError(f"no such contact {cid}")
            return {"effectRef": op, "observed": {"deleted": True, "contactId": cid}}
        if call.action == "manage_crm_objects.read":
            cid = call.payload["contactId"]
            return {"effectRef": op, "observed": {"contactId": cid}}
        raise ValueError(f"adapter cannot serve {call.action}")


@dataclass
class LocalChannelAdapter:
    """A trivial in-process channel. Owns transport authenticity (here: a shared
    secret on the inbound event) and deliverability -- never authorization."""

    inbound_secret: str = "channel-hmac-secret"
    outbox: list = field(default_factory=list)

    def verify_inbound(self, raw: dict) -> bool:
        return raw.get("channelSecret") == self.inbound_secret

    def emit(self, session_id: str, content: dict) -> None:
        self.outbox.append({"sessionId": session_id, "content": content})
