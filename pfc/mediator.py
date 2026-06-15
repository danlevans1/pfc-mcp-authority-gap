"""The PFC mediator -- the enforcement point (Agent B / executingAgent).

Per pfc-mediated-agent: the LLM is NOT a chain principal. It emits an untrusted
``ActionRequest``; the mediator maps it onto a ``ConnectorCall``, runs the
delegation-chain verification, fixes a BoundaryReceipt status at issuance, and
only on PRE_EFFECT lets a credentialed ResourceAdapter act.

Firm invariants enforced here:
  1. Credential starvation -- the mediator holds the signing key; adapters hold
     resource credentials; neither is ever exposed to the LLM.
  2. ActionRequest is untrusted -- mapped, never auto-widened.
  3. Total explicit mapping -- unknown type => fail-closed, no effect.
  4. One request -> one BoundaryReceipt -> at most one effect.
  5. Fail-closed everywhere.
  6. Session<->DelegationToken binding with per-request re-verification (the
     revocation lands here on the very next request).
  7. Read-only effects still get a receipt; only conversation/handoff bypass.

All chain/receipt *semantics* are delegated to pfc.verifier and pfc.artifacts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from .artifacts import (
    ConnectorCall,
    FreshnessBound,
    make_boundary_receipt,
    make_execution_result_receipt,
)
from .attested_clock import MockRoughtimeQuorum, result_proof_nonce
from .crypto import KeyPair, jcs, now_iso, sha256_hex
from .verifier import (
    ChainVerificationError,
    VerifierConfig,
    evaluate_authorization,
    policy_hash,
)

# Risk classes whose effects must be anchored to an attested upper-bound proof.
ATTESTED_RISK_CLASSES = ("HIGH",)


# --------------------------------------------------------------------------
# Deployment-supplied contracts (kept thin; no authorization logic in them)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionMapping:
    """One row of the total, explicit ActionRequest->ConnectorCall mapping.
    ``connector``/``tool``/``operation`` and ``risk`` are bound at deployment
    time -- never supplied by the LLM. ``no_effect`` rows (conversation,
    handoff) bypass the chain entirely."""

    connector: str
    tool: str
    operation: str
    risk: str            # "HIGH" | "MEDIUM" | "LOW"
    no_effect: bool = False


class ResourceAdapter(Protocol):
    """Sole holder of a resource system's credentials. Called ONLY after a
    PRE_EFFECT BoundaryReceipt. Returns the minimum needed to confirm the
    authorized effect occurred."""

    call_actions: tuple[str, ...]

    def execute(self, call: ConnectorCall) -> dict: ...


@dataclass
class MediationOutcome:
    status: str                       # "PRE_EFFECT" | "BLOCKED"
    effect_happened: bool
    boundary_receipt: dict
    execution_result: Optional[dict]
    errors: list[ChainVerificationError]
    effect_ref: Optional[str] = None


class Mediator:
    def __init__(
        self,
        *,
        config: VerifierConfig,
        agent_id: str,                # the mediator's agentId (executingAgent)
        key: KeyPair,
        key_id: str,
        mapping: dict[str, ActionMapping],
        resource_adapters: list[ResourceAdapter],
        freshness_bounds: dict[str, FreshnessBound],   # per risk class
        clock: Callable[[], str] = now_iso,
        quorum: Optional[MockRoughtimeQuorum] = None,  # attested clock authority
        max_attestation_window_ms: int = 5_000,
    ):
        self.config = config
        self.agent_id = agent_id
        self.key = key
        self.key_id = key_id
        self.mapping = mapping
        self.freshness_bounds = freshness_bounds
        self.clock = clock
        self.quorum = quorum            # SEPARATE principal: owns its own clock + radius
        self.max_attestation_window_ms = max_attestation_window_ms
        self._routes: dict[str, ResourceAdapter] = {}
        for adapter in resource_adapters:
            for action in adapter.call_actions:
                self._routes[action] = adapter

    def _attest_required(self, risk: str) -> bool:
        return self.quorum is not None and risk in ATTESTED_RISK_CLASSES

    # ----------------------------------------------------------------------

    def handle(self, *, action_request: dict, human_auth: dict, token: dict) -> Optional[MediationOutcome]:
        """Process one untrusted ActionRequest under a session's (human_auth,
        token). Returns None for no-effect requests (conversation/handoff)."""
        rtype = action_request.get("type")
        row = self.mapping.get(rtype)
        if row is None:
            # Unmapped type -> reject fail-closed (never infer).
            raise ValueError(f"unmapped ActionRequest.type {rtype!r}; fail-closed, no effect")
        if row.no_effect:
            return None  # conversation / handoff: nothing to authorize

        # --- map to ConnectorCall. Target/connector come from the mapping
        #     (deployment), NOT from LLM-supplied identifiers. -------------
        call = ConnectorCall(
            connector=row.connector,
            tool=row.tool,
            operation=row.operation,
            payload=dict(action_request.get("params", {})),
            idempotencyKey=action_request.get("requestId"),
        )

        verified_at = self.clock()
        # Per-request fresh capture of the live authority view (the revocation
        # is visible here the instant it is recorded).
        ledger_head = self.config.revocationLog.head(captured_at=verified_at)
        applied_bound = self.freshness_bounds[row.risk].as_dict()
        nonce = uuid.uuid4().hex

        errors = evaluate_authorization(
            self.config,
            human_auth=human_auth,
            token=token,
            requested_action=call.action,
            requested_target=call.target,
            ledger_head=ledger_head,
            verified_at=verified_at,
            nonce=nonce,
            applied_bound=applied_bound,
        )

        status = "PRE_EFFECT" if not errors else "BLOCKED"
        verification = {
            "result": "PASS" if not errors else "FAIL",
            "verifiedAt": verified_at,
            "ledgerHead": ledger_head.as_dict(),
            "freshnessBound": applied_bound,
            "policyHash": policy_hash(self.config, human_auth, token),
            "errors": [e.code for e in errors],
        }
        # Secondary/hardening: a pre-effect lower-bound proof feeds t_lb into the
        # boundary. Bound to the boundary nonce; combined with the post-effect
        # upper-bound proof and maxAttestationWindowMs it bounds the sandwich.
        if status == "PRE_EFFECT" and self._attest_required(row.risk):
            lb = self.quorum.prove(nonce=nonce)   # quorum stamps its own clock
            verification["lowerBoundProof"] = lb.as_dict()
            verification["maxAttestationWindowMs"] = self.max_attestation_window_ms
        boundary = make_boundary_receipt(
            receipt_id="br_" + uuid.uuid4().hex[:12],
            root_receipt_id=human_auth["receiptId"],
            root_receipt_hash=self.config.artifactStore.get_hash(human_auth["receiptId"]),
            token_id=token["tokenId"],
            token_hash=self.config.artifactStore.get_hash(token["tokenId"]),
            executing_agent=self.agent_id,
            executing_agent_key_id=self.key_id,
            requested_action=call.action,
            requested_target=call.target,
            payload_hash=call.payload_hash(),
            nonce=nonce,
            status=status,
            verification=verification,
            issued_at=verified_at,
            mediator_key=self.key,
            idempotency_key=call.idempotencyKey,
        )
        self.config.artifactStore.put_boundary_receipt(boundary)

        if status == "BLOCKED":
            # Fail-closed: no adapter call, no effect. The signed BLOCKED
            # receipt IS the attestation of the denial.
            return MediationOutcome(
                status=status, effect_happened=False, boundary_receipt=boundary,
                execution_result=None, errors=errors,
            )

        # --- PRE_EFFECT only: execute via the credentialed adapter ---------
        adapter = self._routes.get(call.action)
        if adapter is None:
            raise ValueError(f"no ResourceAdapter for {call.action}; fail-closed")
        started_at = self.clock()
        try:
            outcome = adapter.execute(call)
            res_outcome, effect_ref = "SUCCESS", outcome.get("effectRef")
            observed = outcome.get("observed", {})
        except Exception as exc:  # adapter threw -> failed result, fail closed
            res_outcome, effect_ref, observed = "FAILURE", None, {"error": str(exc)}
        completed_at = self.clock()
        er_id = "er_" + uuid.uuid4().hex[:12]
        result_hash = sha256_hex(jcs(observed))
        boundary_hash = self.config.artifactStore.get_hash(boundary["receiptId"])

        # HIGH-class effects MUST anchor to an attested upper bound. The proof's
        # nonce binds H(result content), so it can only be obtained after the
        # effect and the authorities stamp their own honest midpoint. Absence
        # fails closed (the auditor raises ATTESTATION_MISSING).
        time_proof = None
        max_window = None
        if self._attest_required(row.risk):
            # effect_ref is the adapter's unpredictable, post-effect token; the
            # proof nonce binds it, so a proof cannot be pre-fetched.
            nonce_fields = {
                "artifactType": "ExecutionResultReceipt",
                "receiptId": er_id,
                "boundaryReceiptId": boundary["receiptId"],
                "boundaryReceiptHash": boundary_hash,
                "executingAgent": self.agent_id,
                "executingAgentKeyId": self.key_id,
                "observedRequest": {"action": call.action, "target": call.target,
                                    "payloadHash": call.payload_hash()},
                "outcome": res_outcome,
                "resultHash": result_hash,
                "effectRef": effect_ref,
                "startedAt": started_at,
                "completedAt": completed_at,
            }
            ub = self.quorum.prove(nonce=result_proof_nonce(nonce_fields))  # after the effect
            time_proof = ub.as_dict()
            max_window = self.max_attestation_window_ms

        result = make_execution_result_receipt(
            receipt_id=er_id,
            boundary_receipt_id=boundary["receiptId"],
            boundary_receipt_hash=boundary_hash,
            executing_agent=self.agent_id,
            executing_agent_key_id=self.key_id,
            observed_action=call.action,
            observed_target=call.target,
            observed_payload_hash=call.payload_hash(),
            outcome=res_outcome,
            result_hash=result_hash,
            effect_ref=effect_ref,
            started_at=started_at,
            completed_at=completed_at,
            mediator_key=self.key,
            time_proof=time_proof,
            max_attestation_window_ms=max_window,
        )
        self.config.artifactStore.put_execution_result_receipt(result)
        return MediationOutcome(
            status=status, effect_happened=(res_outcome == "SUCCESS"),
            boundary_receipt=boundary, execution_result=result,
            errors=errors, effect_ref=effect_ref,
        )
