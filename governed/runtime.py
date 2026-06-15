"""AgentRuntime + a stub "LLM".

The LLM is NOT a chain principal: it owns no key in the KeyRegistry, signs
nothing, holds no credential, and cannot widen its own authority. Its only
structured output is an untrusted ``ActionRequest`` drawn from a CLOSED enum.
The runtime hands that ActionRequest to the mediator and returns whatever the
mediator decides.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from pfc import Mediator

# Closed ActionRequestType enum for this deployment.
DELETE_CONTACT = "DELETE_CONTACT"
READ_CONTACT = "READ_CONTACT"
HANDOFF = "HANDOFF"


def stub_llm(instruction: str, session_id: str) -> dict:
    """Pretend reasoning step. Maps a natural-language instruction to ONE
    ActionRequest. A real LLM would emit this via a constrained tool interface;
    the mediator treats it as untrusted either way. Note: no timestamp, no
    target identifier the LLM could redirect, no credential."""
    text = instruction.lower()
    if "delete" in text:
        cid = instruction.split()[-1]
        return {"requestId": uuid.uuid4().hex, "sessionId": session_id,
                "type": DELETE_CONTACT, "params": {"contactId": cid}}
    if "read" in text or "look up" in text:
        cid = instruction.split()[-1]
        return {"requestId": uuid.uuid4().hex, "sessionId": session_id,
                "type": READ_CONTACT, "params": {"contactId": cid}}
    return {"requestId": uuid.uuid4().hex, "sessionId": session_id,
            "type": HANDOFF, "params": {}}


@dataclass
class AgentRuntime:
    mediator: Mediator
    human_auth: dict
    token: dict
    session_id: str = "sess-1"

    def handle_instruction(self, instruction: str):
        action_request = stub_llm(instruction, self.session_id)
        # Per-request: the mediator re-resolves and re-verifies the session's
        # token, so a mid-session revocation blocks the very next request.
        return self.mediator.handle(
            action_request=action_request,
            human_auth=self.human_auth,
            token=self.token,
        )
