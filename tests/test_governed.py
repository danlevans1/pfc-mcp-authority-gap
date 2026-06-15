"""The governed path DENIES, THEN ATTESTS: the PFC mediator re-verifies the
delegation chain on every request, blocks the revoked authority before any
effect, and emits a signed receipt that an independent auditor verifies without
trusting the mediator."""

import json
from datetime import timedelta

import pytest

from governed import auditor
from governed.runtime import HANDOFF, stub_llm
from governed.setup import MEDIATOR, T0, build_world
from pfc import RevocationEntry
from pfc.artifacts import ConnectorCall, make_boundary_receipt, make_execution_result_receipt
from pfc.crypto import hash_artifact, iso
from pfc.ledgers import LedgerHeadRef
from pfc.verifier import evaluate_authorization, policy_hash


def _world_with_revocation_after_issuance():
    w = build_world()
    w.clock.set_seconds_from_base(T0, 0)
    out1 = w.runtime.handle_instruction("delete c-1002")     # allowed
    w.revocation_log.revoke(RevocationEntry(
        "har-1", iso(T0 + timedelta(seconds=300)),
        "security incident: authority pulled", "user:dana(admin)"))
    w.clock.set_seconds_from_base(T0, 600)
    out2 = w.runtime.handle_instruction("delete c-1001")     # revoked
    return w, out1, out2


# --------------------------------------------------------------------------
# Allowed request emits the full four-artifact chain and audits valid.
# --------------------------------------------------------------------------


def test_allowed_request_emits_full_chain_and_audits_valid():
    w = build_world()
    w.clock.set_seconds_from_base(T0, 0)
    out1 = w.runtime.handle_instruction("delete c-1002")
    assert out1.status == "PRE_EFFECT"
    assert out1.effect_happened is True
    assert out1.execution_result is not None          # ExecutionResultReceipt present
    bundle = auditor.bundle_from_world(w, out1.boundary_receipt, out1.execution_result)
    res = auditor.audit(bundle)
    assert res.valid is True
    assert res.chainIntact is True
    assert res.errors == []


def test_point_in_time_authorization_survives_later_revocation():
    """Revocation is POINT-IN-TIME: an action that ran before the revokedAt
    stays authorized-at-execution. Re-auditing it after the authority is pulled
    reports authorizedAtExecution=True but authorityLiveNow=False -- it never
    reads as 'never authorized' merely because authority was later revoked."""
    w, out1, _ = _world_with_revocation_after_issuance()
    res = auditor.audit(auditor.bundle_from_world(w, out1.boundary_receipt, out1.execution_result))
    assert res.chainIntact is True
    assert res.authorizedAtExecution is True      # ran at T0, before revokedAt T0+300
    assert res.authorityLiveNow is False          # authority since pulled
    assert res.valid is True                       # valid aliases authorizedAtExecution
    assert "ROOT_RECEIPT_REVOKED" not in res.codes()


def test_revoked_request_distinguishes_the_two_verdicts():
    """The blocked request was never authorized at its own execution time AND
    the authority is not live now -- both verdicts are False."""
    w, _, out2 = _world_with_revocation_after_issuance()
    res = auditor.audit(auditor.bundle_from_world(w, out2.boundary_receipt, None))
    assert res.authorizedAtExecution is False
    assert res.authorityLiveNow is False
    assert "ROOT_RECEIPT_REVOKED" in res.codes()


def test_authority_live_now_is_evaluated_as_of_evaluatedAt():
    """authorityLiveNow is evaluated as of the bundle's evaluatedAt (overridable),
    not wall-clock now. A pre-revocation action stays authorizedAtExecution=True
    at every evaluatedAt; authorityLiveNow flips only once evaluatedAt crosses
    the revokedAt."""
    w, out1, _ = _world_with_revocation_after_issuance()           # revokedAt = T0+300
    bundle = auditor.bundle_from_world(w, out1.boundary_receipt, out1.execution_result)

    after = auditor.audit(bundle, evaluated_at=iso(T0 + timedelta(seconds=1000)))
    assert after.authorizedAtExecution is True                     # ran at T0
    assert after.authorityLiveNow is False                         # revoked by T0+1000

    before = auditor.audit(bundle, evaluated_at=iso(T0 + timedelta(seconds=100)))
    assert before.authorizedAtExecution is True
    assert before.authorityLiveNow is True                         # not yet revoked at T0+100


# --------------------------------------------------------------------------
# Revoked authority: fail-closed before any effect, and attested.
# --------------------------------------------------------------------------


def test_revoked_authority_is_blocked_with_no_effect():
    w, _, out2 = _world_with_revocation_after_issuance()
    assert out2.status == "BLOCKED"
    assert out2.effect_happened is False
    assert out2.execution_result is None              # adapter never invoked
    assert "c-1001" in w.adapter.contacts             # the effect did NOT happen


def test_blocked_request_is_independently_verifiable():
    w, _, out2 = _world_with_revocation_after_issuance()
    bundle = auditor.bundle_from_world(w, out2.boundary_receipt, None)
    res = auditor.audit(bundle)
    # The denial is cryptographically sound (a real, signed attestation)...
    assert res.chainIntact is True
    assert res.freshnessSatisfied is True
    # ...and the verdict is a genuine deny for the right reason.
    assert res.valid is False
    assert "ROOT_RECEIPT_REVOKED" in res.codes()


# --------------------------------------------------------------------------
# Trustless: a mediator that LIES about the status is caught, even re-signed.
# --------------------------------------------------------------------------


def test_auditor_catches_forged_pre_effect_status():
    w, _, out2 = _world_with_revocation_after_issuance()
    br = out2.boundary_receipt
    # A malicious/buggy mediator re-signs a PRE_EFFECT receipt for the revoked
    # request using its own (legitimate) key.
    forged_verification = {
        "result": "PASS",
        "verifiedAt": br["verification"]["verifiedAt"],
        "ledgerHead": br["verification"]["ledgerHead"],
        "freshnessBound": br["verification"]["freshnessBound"],
        "policyHash": br["verification"]["policyHash"],
        "errors": [],
    }
    forged = make_boundary_receipt(
        receipt_id="br_forged",
        root_receipt_id=br["root"]["receiptId"],
        root_receipt_hash=br["root"]["receiptHash"],
        token_id=br["delegation"]["tokenId"],
        token_hash=br["delegation"]["tokenHash"],
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        requested_action=br["requestedAction"],
        requested_target=br["requestedTarget"],
        payload_hash=br["payloadHash"],
        nonce=br["nonce"],
        status="PRE_EFFECT",
        verification=forged_verification,
        issued_at=br["issuedAt"],
        mediator_key=w.mediator.key,          # validly signed!
        idempotency_key=br.get("idempotencyKey"),
    )
    res = auditor.audit(auditor.bundle_from_world(w, forged, None))
    # Signature + hash bindings still hold, so the chain is "intact"...
    assert res.chainIntact is True
    # ...but the auditor recomputes the verdict from the ledgers and refuses it.
    assert res.valid is False
    assert "CHAIN_INTEGRITY_VIOLATION" in res.codes()
    assert "ROOT_RECEIPT_REVOKED" in res.codes()


# --------------------------------------------------------------------------
# Authority-signed ledger head: forging a fresh capturedAt is caught.
# --------------------------------------------------------------------------


def test_forged_fresh_capturedat_over_stale_head_is_caught():
    """A stale head is authentically signed over its OLD capturedAt. A mediator
    that swaps in a fresh capturedAt (to beat the freshness bound) cannot
    re-sign the head -- it lacks the revocation-service key -- so the auditor's
    head-signature check fails."""
    w = build_world()
    verified_at = iso(T0)
    stale_capture = iso(T0 - timedelta(seconds=120))      # older than 30s HIGH bound
    signed_stale = w.revocation_log.head(captured_at=stale_capture)  # authority-signed

    forged_head = dict(signed_stale.as_dict())
    forged_head["capturedAt"] = verified_at               # looks fresh; signature now stale
    assert forged_head["signature"] == signed_stale.signature  # signature NOT re-made

    call = ConnectorCall("crm", "manage_crm_objects", "delete", {"contactId": "c-1001"})
    verification = {
        "result": "PASS",
        "verifiedAt": verified_at,
        "ledgerHead": forged_head,
        "freshnessBound": {"maxAgeMs": 30_000, "riskClass": "HIGH"},
        "policyHash": policy_hash(w.config, w.human_auth, w.token),
        "errors": [],
    }
    forged_boundary = make_boundary_receipt(
        receipt_id="br_forgedhead",
        root_receipt_id="har-1",
        root_receipt_hash=w.config.artifactStore.get_hash("har-1"),
        token_id="dt-1",
        token_hash=w.config.artifactStore.get_hash("dt-1"),
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        requested_action=call.action,
        requested_target=call.target,
        payload_hash=call.payload_hash(),
        nonce="n-forged",
        status="PRE_EFFECT",
        verification=verification,
        issued_at=verified_at,
        mediator_key=w.mediator.key,          # boundary itself is validly signed
    )
    res = auditor.audit(auditor.bundle_from_world(w, forged_boundary, None))
    assert res.chainIntact is True             # the boundary's own signature holds
    assert res.freshnessSatisfied is False     # but the head is not authority-signed
    assert "FRESHNESS_VIOLATION" in res.codes()
    assert res.authorizedAtExecution is False


# --------------------------------------------------------------------------
# Backdating + pre-revocation signed head is caught by the cross-check.
# --------------------------------------------------------------------------


def test_backdated_verifiedat_with_prerevocation_head_is_caught():
    """A mediator quotes an AUTHENTIC pre-revocation head (capturedAt=T0, seq 0)
    and backdates verifiedAt to T0 so the age check passes -- but the action
    actually completed at T0+600, after a revocation at T0+300. The stale-head
    cross-check ties the head to the action's completion time and catches it,
    even though every signature is valid."""
    w = build_world()
    # An authentic head captured BEFORE any revocation.
    pre_head = w.revocation_log.head(captured_at=iso(T0))          # seq 0, rev-key signed
    # Authority is then revoked at T0+300 (seq 1).
    w.revocation_log.revoke(RevocationEntry(
        "har-1", iso(T0 + timedelta(seconds=300)), "incident", "user:dana(admin)"))

    call = ConnectorCall("crm", "manage_crm_objects", "delete", {"contactId": "c-1001"})
    backdated = iso(T0)                                            # mediator backdates verifiedAt
    verification = {
        "result": "PASS",
        "verifiedAt": backdated,
        "ledgerHead": pre_head.as_dict(),                          # authentic, but pre-revocation
        "freshnessBound": {"maxAgeMs": 30_000, "riskClass": "HIGH"},
        "policyHash": policy_hash(w.config, w.human_auth, w.token),
        "errors": [],
    }
    boundary = make_boundary_receipt(
        receipt_id="br_backdated",
        root_receipt_id="har-1",
        root_receipt_hash=w.config.artifactStore.get_hash("har-1"),
        token_id="dt-1",
        token_hash=w.config.artifactStore.get_hash("dt-1"),
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        requested_action=call.action,
        requested_target=call.target,
        payload_hash=call.payload_hash(),
        nonce="n-backdated",
        status="PRE_EFFECT",
        verification=verification,
        issued_at=backdated,
        mediator_key=w.mediator.key,
    )
    # The result records the HONEST completion time, after the revocation.
    result = make_execution_result_receipt(
        receipt_id="er_backdated",
        boundary_receipt_id=boundary["receiptId"],
        boundary_receipt_hash=hash_artifact(boundary),
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        observed_action=call.action,
        observed_target=call.target,
        observed_payload_hash=call.payload_hash(),
        outcome="SUCCESS",
        result_hash="0" * 64,
        started_at=iso(T0 + timedelta(seconds=600)),
        completed_at=iso(T0 + timedelta(seconds=600)),
        mediator_key=w.mediator.key,
    )
    res = auditor.audit(auditor.bundle_from_world(w, boundary, result))
    assert res.chainIntact is True                  # every signature/ hash is valid
    assert res.freshnessSatisfied is False
    assert "STALE_HEAD_VS_KNOWN_REVOCATION" in res.codes()
    assert res.authorizedAtExecution is False       # the backdating attack fails


# --------------------------------------------------------------------------
# Per-action-class freshness bound is enforced.
# --------------------------------------------------------------------------


def test_stale_ledger_view_triggers_freshness_violation():
    w = build_world()
    verified_at = iso(T0)
    stale_head = LedgerHeadRef(0, "h", iso(T0 - timedelta(seconds=120)))  # 120s old
    errs = evaluate_authorization(
        w.config,
        human_auth=w.human_auth,
        token=w.token,
        requested_action="manage_crm_objects.delete",
        requested_target="crm:manage_crm_objects",
        ledger_head=stale_head,
        verified_at=verified_at,
        applied_bound={"maxAgeMs": 30_000, "riskClass": "HIGH"},  # 30s
        consume_nonce=False,
        consume_usage=False,
    )
    assert "FRESHNESS_VIOLATION" in [e.code for e in errs]


# --------------------------------------------------------------------------
# Credential starvation + fail-closed mapping (pfc-mediated-agent firm rules).
# --------------------------------------------------------------------------


def test_llm_output_holds_no_key_or_credential():
    ar = stub_llm("delete c-1001", "sess-1")
    blob = json.dumps(ar).lower()
    for forbidden in ("key", "credential", "secret", "bearer", "signature"):
        assert forbidden not in blob
    w = build_world()
    # The signing key lives on the mediator; the credential lives on the adapter.
    assert w.mediator.key is not None
    assert w.adapter._credential


def test_unmapped_action_type_fails_closed():
    w = build_world()
    with pytest.raises(ValueError):
        w.mediator.handle(
            action_request={"requestId": "r1", "sessionId": "s", "type": "WIRE_MONEY", "params": {}},
            human_auth=w.human_auth,
            token=w.token,
        )


def test_handoff_is_no_effect_and_bypasses_chain():
    w = build_world()
    out = w.mediator.handle(
        action_request=stub_llm("can you help me", "sess-1"),
        human_auth=w.human_auth,
        token=w.token,
    )
    assert out is None  # conversation/handoff: nothing to authorize
