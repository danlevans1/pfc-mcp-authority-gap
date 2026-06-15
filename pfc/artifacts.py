"""The four chain artifacts and supporting value types.

Shapes transcribed from pfc-delegation-chain references/types.ts (v0.13).
Artifacts are plain dicts so that JCS canonicalization, hashing and signing are
uniform across the chain. Builder functions sign the body and return the signed,
immutable dict.

  HumanAuthReceipt              signed by governance layer
    -> DelegationToken          signed by Agent A
         -> BoundaryReceipt     signed by Agent B (PRE-EFFECT / BLOCKED at issuance)
              -> ExecutionResultReceipt  signed by Agent B (POST-EFFECT)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import KeyPair, jcs, sha256_hex

# --------------------------------------------------------------------------
# Value types
# --------------------------------------------------------------------------

RiskClass = str  # "HIGH" | "MEDIUM" | "LOW"


@dataclass(frozen=True)
class FreshnessBound:
    maxAgeMs: int
    riskClass: RiskClass

    def as_dict(self) -> dict:
        return {"maxAgeMs": self.maxAgeMs, "riskClass": self.riskClass}


@dataclass(frozen=True)
class ConnectorCall:
    """Gateway-facing call shape (not a chain artifact). Maps an MCP connector
    call onto the spec's action/target scope model."""

    connector: str          # e.g. "hubspot"
    tool: str               # e.g. "manage_crm_objects"
    operation: str          # e.g. "delete"
    payload: dict
    idempotencyKey: Optional[str] = None

    @property
    def action(self) -> str:
        return f"{self.tool}.{self.operation}"

    @property
    def target(self) -> str:
        return f"{self.connector}:{self.tool}"

    def payload_hash(self) -> str:
        return sha256_hex(jcs(self.payload))


# --------------------------------------------------------------------------
# Artifact builders -- each signs the body and returns the signed dict.
# --------------------------------------------------------------------------


def make_human_auth_receipt(
    *,
    receipt_id: str,
    authorized_agent: str,
    granted_by: str,
    authority_issued_at: str,
    permitted_actions: list[str],
    permitted_targets: list[str],
    usage_policy: str,          # "SINGLE_USE" | "MULTI_USE"
    issued_at: str,
    expires_at: str,
    issuer_key_id: str,
    governance_key: KeyPair,
    max_uses: Optional[int] = None,
) -> dict:
    body = {
        "artifactType": "HumanAuthReceipt",
        "receiptId": receipt_id,
        "authorizedAgent": authorized_agent,
        "authority": {"grantedBy": granted_by, "issuedAt": authority_issued_at},
        "permittedActions": permitted_actions,
        "permittedTargets": permitted_targets,
        "usagePolicy": usage_policy,
        "maxUses": max_uses,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "issuerKeyId": issuer_key_id,
    }
    body["signature"] = governance_key.sign_body(body)
    return body


def make_delegation_token(
    *,
    token_id: str,
    issuer_agent_id: str,
    issuer_key_id: str,
    parent_receipt_id: str,
    parent_receipt_hash: str,
    delegatee_agent_id: str,
    delegatee_key_id: str,
    permitted_actions: list[str],
    permitted_targets: list[str],
    freshness_bound: FreshnessBound,
    issued_at: str,
    expires_at: str,
    issuer_key: KeyPair,
) -> dict:
    body = {
        "artifactType": "DelegationToken",
        "tokenId": token_id,
        "issuer": {
            "agentId": issuer_agent_id,
            "keyId": issuer_key_id,
            "parentReceiptId": parent_receipt_id,
            "parentReceiptHash": parent_receipt_hash,
        },
        "delegatee": {"agentId": delegatee_agent_id, "keyId": delegatee_key_id},
        "permittedActions": permitted_actions,
        "permittedTargets": permitted_targets,
        "freshnessBound": freshness_bound.as_dict(),
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    body["signature"] = issuer_key.sign_body(body)
    return body


def make_boundary_receipt(
    *,
    receipt_id: str,
    root_receipt_id: str,
    root_receipt_hash: str,
    token_id: str,
    token_hash: str,
    executing_agent: str,
    executing_agent_key_id: str,
    requested_action: str,
    requested_target: str,
    payload_hash: str,
    nonce: str,
    status: str,                       # "PRE_EFFECT" | "BLOCKED"
    verification: dict,                # BoundaryVerification dict
    issued_at: str,
    mediator_key: KeyPair,
    idempotency_key: Optional[str] = None,
) -> dict:
    body = {
        "artifactType": "BoundaryReceipt",
        "receiptId": receipt_id,
        "root": {"receiptId": root_receipt_id, "receiptHash": root_receipt_hash},
        "delegation": {"tokenId": token_id, "tokenHash": token_hash},
        "executingAgent": executing_agent,
        "executingAgentKeyId": executing_agent_key_id,
        "requestedAction": requested_action,
        "requestedTarget": requested_target,
        "payloadHash": payload_hash,
        "nonce": nonce,
        "idempotencyKey": idempotency_key,
        "status": status,
        "verification": verification,
        "issuedAt": issued_at,
    }
    body["signature"] = mediator_key.sign_body(body)
    return body


def make_execution_result_receipt(
    *,
    receipt_id: str,
    boundary_receipt_id: str,
    boundary_receipt_hash: str,
    executing_agent: str,
    executing_agent_key_id: str,
    observed_action: str,
    observed_target: str,
    observed_payload_hash: str,
    outcome: str,                      # "SUCCESS" | "FAILURE"
    result_hash: str,
    started_at: str,
    completed_at: str,
    mediator_key: KeyPair,
    effect_ref: Optional[str] = None,              # unpredictable, server-assigned
    time_proof: Optional[dict] = None,             # upper-bound TimeProof (HIGH effects)
    max_attestation_window_ms: Optional[int] = None,
) -> dict:
    # NOTE: the upper-bound proof's nonce binds H over exactly the fields below
    # (RESULT_NONCE_FIELDS in attested_clock); timeProof / maxAttestationWindowMs
    # are added AFTER the nonce is computed but are still covered by the signature.
    body = {
        "artifactType": "ExecutionResultReceipt",
        "receiptId": receipt_id,
        "boundaryReceiptId": boundary_receipt_id,
        "boundaryReceiptHash": boundary_receipt_hash,
        "executingAgent": executing_agent,
        "executingAgentKeyId": executing_agent_key_id,
        "observedRequest": {
            "action": observed_action,
            "target": observed_target,
            "payloadHash": observed_payload_hash,
        },
        "outcome": outcome,
        "resultHash": result_hash,
        "effectRef": effect_ref,
        "startedAt": started_at,
        "completedAt": completed_at,
        "timeProof": time_proof,
        "maxAttestationWindowMs": max_attestation_window_ms,
    }
    body["signature"] = mediator_key.sign_body(body)
    return body
