"""Attested-clock anchoring closes the last backdating seam.

The time authority is a SEPARATE principal: the quorum stamps its OWN clock and
its OWN radius, so a mediator cannot move t_ub by lying about its clock. The
upper-bound proof's nonce binds an UNPREDICTABLE post-effect token (effectRef),
so a proof cannot be pre-fetched against a guessed result. And the required risk
class is bound into the SIGNED policy, so a HIGH action cannot be relabelled LOW
to skip attestation."""

import uuid
from datetime import timedelta

from governed import auditor
from governed.setup import MEDIATOR, T0, build_world
from pfc import RevocationEntry
from pfc.artifacts import ConnectorCall, make_boundary_receipt, make_execution_result_receipt
from pfc.attested_clock import result_proof_nonce
from pfc.crypto import hash_artifact, iso
from pfc.verifier import policy_hash

CALL = ConnectorCall("crm", "manage_crm_objects", "delete", {"contactId": "c-1001"})


def _at(seconds):
    return iso(T0 + timedelta(seconds=seconds))


def _high_chain(w, *, verified_s, completed_s, upper_mid_s, lower_mid_s=None,
                risk_label="HIGH", effect_ref="op-real", proof_effect_ref=None,
                upper="auto", upper_nonce=None, head=None, corrupt_ids=(),
                signer_ids=None, max_window=5_000):
    """Build a HIGH delete chain with full control over the attested-clock
    proofs, signed with the world's real keys (the threat actor IS the mediator).
    Proof midpoints come from the quorum's own clock, set per prove() call."""
    nonce = "n-" + uuid.uuid4().hex[:8]
    verified_at, completed_at = _at(verified_s), _at(completed_s)
    head = head or w.revocation_log.head(captured_at=verified_at)
    verification = {
        "result": "PASS",
        "verifiedAt": verified_at,
        "ledgerHead": head.as_dict(),
        "freshnessBound": {"maxAgeMs": 30_000, "riskClass": risk_label},   # may be mislabelled
        "policyHash": policy_hash(w.config, w.human_auth, w.token),
        "errors": [],
    }
    if lower_mid_s is not None:
        w.quorum_clock.set_seconds_from_base(T0, lower_mid_s)
        verification["lowerBoundProof"] = w.quorum.prove(nonce=nonce).as_dict()
        verification["maxAttestationWindowMs"] = max_window

    boundary = make_boundary_receipt(
        receipt_id="br-" + uuid.uuid4().hex[:8],
        root_receipt_id="har-1",
        root_receipt_hash=w.config.artifactStore.get_hash("har-1"),
        token_id="dt-1",
        token_hash=w.config.artifactStore.get_hash("dt-1"),
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        requested_action=CALL.action,
        requested_target=CALL.target,
        payload_hash=CALL.payload_hash(),
        nonce=nonce,
        status="PRE_EFFECT",
        verification=verification,
        issued_at=verified_at,
        mediator_key=w.mediator.key,
    )

    er_id = "er-" + uuid.uuid4().hex[:8]
    boundary_hash = hash_artifact(boundary)
    proof_eref = proof_effect_ref if proof_effect_ref is not None else effect_ref
    nonce_fields = {
        "artifactType": "ExecutionResultReceipt",
        "receiptId": er_id,
        "boundaryReceiptId": boundary["receiptId"],
        "boundaryReceiptHash": boundary_hash,
        "executingAgent": MEDIATOR,
        "executingAgentKeyId": "b-key",
        "observedRequest": {"action": CALL.action, "target": CALL.target, "payloadHash": CALL.payload_hash()},
        "outcome": "SUCCESS",
        "resultHash": "0" * 64,
        "effectRef": proof_eref,
        "startedAt": verified_at,
        "completedAt": completed_at,
    }
    time_proof = None
    if upper == "auto":
        w.quorum_clock.set_seconds_from_base(T0, upper_mid_s)
        time_proof = w.quorum.prove(
            nonce=upper_nonce or result_proof_nonce(nonce_fields),
            corrupt_ids=corrupt_ids, signer_ids=signer_ids).as_dict()

    result = make_execution_result_receipt(
        receipt_id=er_id,
        boundary_receipt_id=boundary["receiptId"],
        boundary_receipt_hash=boundary_hash,
        executing_agent=MEDIATOR,
        executing_agent_key_id="b-key",
        observed_action=CALL.action,
        observed_target=CALL.target,
        observed_payload_hash=CALL.payload_hash(),
        outcome="SUCCESS",
        result_hash="0" * 64,
        effect_ref=effect_ref,
        started_at=verified_at,
        completed_at=completed_at,
        mediator_key=w.mediator.key,
        time_proof=time_proof,
        max_attestation_window_ms=max_window if time_proof else None,
    )
    return boundary, result


def _audit(w, boundary, result):
    return auditor.audit(auditor.bundle_from_world(w, boundary, result))


# --------------------------------------------------------------------------
# Honest path.
# --------------------------------------------------------------------------


def test_honest_pre_revocation_action_with_tight_sandwich_is_authorized():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0, lower_mid_s=0)
    res = _audit(w, b, r)
    assert res.errors == []
    assert res.authorizedAtExecution is True


# --------------------------------------------------------------------------
# Flaw 1: the quorum is a real, independent time authority.
# --------------------------------------------------------------------------


def test_all_timestamps_backdating_is_caught_by_independent_quorum_clock():
    """The mediator backdates its OWN clock to T0 (so issuance passes) and dates
    every self-asserted timestamp at T0. But the time authority's clock is
    honestly at T0+600, so the quorum stamps midpoint ~ T0+600, t_ub > the
    T0+300 revocation, and the action is denied."""
    w = build_world()
    w.revocation_log.revoke(RevocationEntry(
        "har-1", _at(300), "incident", "user:dana(admin)"))
    w.clock.set_seconds_from_base(T0, 0)            # mediator lies: backdates its own clock
    w.quorum_clock.set_seconds_from_base(T0, 600)   # the time authority is honestly later

    out = w.runtime.handle_instruction("delete c-1001")
    assert out.status == "PRE_EFFECT"               # backdated mediator clock let issuance pass
    res = _audit(w, out.boundary_receipt, out.execution_result)
    assert res.chainIntact is True                  # all signatures valid
    assert res.authorizedAtExecution is False
    assert "ROOT_RECEIPT_REVOKED" in res.codes()    # revocation effective by attested t_ub


def test_mediator_cannot_move_t_ub_by_changing_its_own_clock():
    """Guard: prove() stamps the quorum's own clock and ignores the mediator's."""
    w = build_world()
    w.quorum_clock.set_seconds_from_base(T0, 0)
    w.clock.set_seconds_from_base(T0, 0)
    p1 = w.quorum.prove(nonce="x")
    w.clock.set_seconds_from_base(T0, 9_999)        # mediator clock jumps wildly
    p2 = w.quorum.prove(nonce="x")
    assert p1.midpoint == p2.midpoint == iso(T0)    # unaffected by the mediator clock


def test_prefetched_or_wrong_nonce_upper_proof_is_unbound():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0,
                       upper_nonce="dead" * 16)
    res = _audit(w, b, r)
    assert "ATTESTATION_NONCE_UNBOUND" in res.codes()
    assert res.authorizedAtExecution is False


def test_high_effect_without_proof_is_missing():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0, upper=None)
    res = _audit(w, b, r)
    assert "ATTESTATION_MISSING" in res.codes()
    assert res.authorizedAtExecution is False


def test_stale_lower_bound_exceeds_window():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0,
                       lower_mid_s=-100, max_window=5_000)   # stale lower bound
    res = _audit(w, b, r)
    assert "ATTESTATION_WINDOW_EXCEEDED" in res.codes()
    assert res.authorizedAtExecution is False


def test_single_server_compromise_with_quorum_intact_still_verifies():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0, lower_mid_s=0,
                       corrupt_ids=(w.time_authority_ids[0],))   # 4 of 5 valid >= 3
    res = _audit(w, b, r)
    assert res.errors == []
    assert res.authorizedAtExecution is True


def test_broken_quorum_is_rejected():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0, lower_mid_s=0,
                       corrupt_ids=tuple(w.time_authority_ids[:3]))   # 2 of 5 valid < 3
    res = _audit(w, b, r)
    assert "ATTESTATION_QUORUM_NOT_MET" in res.codes()
    assert "ATTESTATION_INVALID_SIGNATURE" in res.codes()
    assert res.authorizedAtExecution is False


# --------------------------------------------------------------------------
# Flaw 2: risk class is bound into the signed policy.
# --------------------------------------------------------------------------


def test_high_action_mislabelled_low_to_skip_attestation_is_caught():
    """A mediator labels a HIGH delete `LOW` (and attaches no proof) to dodge
    attestation. The auditor takes the required risk from the SIGNED policy
    (delete -> HIGH), not the boundary's label, and demands attestation."""
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0,
                       risk_label="LOW", upper=None)
    res = _audit(w, b, r)
    assert "ATTESTATION_MISSING" in res.codes()
    assert res.authorizedAtExecution is False


# --------------------------------------------------------------------------
# Flaw 3: the proof binds an unpredictable post-effect token.
# --------------------------------------------------------------------------


def test_prefetched_proof_cannot_match_unpredictable_effectref():
    """Attacker pre-computes a deterministic result and obtains an honest-clock
    proof at T0 (before performing the effect). The real effectRef is assigned
    by the resource only at execution (T0+600) and is unknown at T0, so the
    pre-fetched proof's nonce cannot match the real result."""
    w = build_world()
    real_effect_ref = "op-" + uuid.uuid4().hex      # unknowable at pre-fetch time
    b, r = _high_chain(
        w,
        verified_s=0, completed_s=0, upper_mid_s=0,   # proof honestly stamped at T0
        proof_effect_ref="op-GUESS-at-T0",            # what the attacker could bind at T0
        effect_ref=real_effect_ref,                   # what the effect actually produced
    )
    res = _audit(w, b, r)
    assert "ATTESTATION_NONCE_UNBOUND" in res.codes()
    assert res.authorizedAtExecution is False


def test_high_effect_without_effectref_is_rejected():
    w = build_world()
    b, r = _high_chain(w, verified_s=0, completed_s=0, upper_mid_s=0, effect_ref="")
    res = _audit(w, b, r)
    assert "ATTESTATION_MISSING" in res.codes()
    assert res.authorizedAtExecution is False
