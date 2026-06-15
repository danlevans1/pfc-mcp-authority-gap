"""Chain verifier.

Implements the pfc-delegation-chain verification semantics for this repo's
artifact set. Two entry points share one body of invariant checks:

  * ``evaluate_authorization`` -- the issuance-time decision the *mediator*
    runs before it fixes a BoundaryReceipt's status (PASS -> PRE_EFFECT,
    FAIL -> BLOCKED). Fail-closed: any error => deny.

  * ``verify_chain`` -- the *replay* verification the auditor runs over stored,
    signed artifacts. It re-derives crypto soundness (``chainIntact``), the
    freshness view (``freshnessSatisfied``) and the authorization outcome
    (``valid``) WITHOUT trusting any claim the mediator wrote into the receipt.
    Critically, it recomputes the authorization decision from the ledgers and
    compares it to the boundary's asserted status, so a mediator that issued
    PRE_EFFECT when authority was revoked is caught.

``chainIntact`` excludes scope/expiry/revocation/nonce/authorization outcome --
only crypto + structural resolution -- so "correctly blocked" is distinguished
from "cryptographically broken".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .attested_clock import (
    ATTESTATION_INTERVAL_INCONSISTENT,
    ATTESTATION_MISSING,
    ATTESTATION_WINDOW_EXCEEDED,
    result_proof_nonce,
    verify_time_proof,
)
from .crypto import (
    add_ms,
    hash_artifact,
    jcs,
    ms_between,
    now_iso,
    sha256_hex,
    verify_signature,
)
from .ledgers import (
    ArtifactStore,
    IdempotencyLog,
    KeyRegistry,
    LedgerHeadRef,
    NonceLog,
    REVOCATION_SERVICE_OWNER,
    RevocationLog,
    UsageLedger,
)

GOVERNANCE_OWNER = "governance-layer"

# Repo-local error code beyond the canonical v0.13 ChainVerificationError
# vocabulary (which the pfc-delegation-chain skill owns). Raised by the
# stale-head / known-revocation cross-check in verify_chain.
STALE_HEAD_VS_KNOWN_REVOCATION = "STALE_HEAD_VS_KNOWN_REVOCATION"


@dataclass
class ChainVerificationError:
    code: str
    message: str
    artifactId: Optional[str] = None

    def __str__(self) -> str:
        loc = f" [{self.artifactId}]" if self.artifactId else ""
        return f"{self.code}: {self.message}{loc}"


@dataclass
class ChainVerificationResult:
    valid: bool                  # alias of authorizedAtExecution (back-compat)
    chainIntact: bool
    freshnessSatisfied: bool
    # Two distinct verdicts (point-in-time vs. present):
    #   authorizedAtExecution -- was the action authorized AS OF its own
    #     verifiedAt/completedAt? A past-valid action stays True even after the
    #     authority is later pulled.
    #   authorityLiveNow -- is the authority still live at audit time? Goes
    #     False the instant a revocation with revokedAt <= now exists.
    authorizedAtExecution: bool = False
    authorityLiveNow: bool = True
    errors: list[ChainVerificationError] = field(default_factory=list)
    chain: dict = field(default_factory=dict)

    def codes(self) -> list[str]:
        return [e.code for e in self.errors]


@dataclass
class VerifierConfig:
    version: str
    clockSkewToleranceMs: int
    keyRegistry: KeyRegistry
    revocationLog: RevocationLog
    nonceLog: NonceLog
    usageLedger: UsageLedger
    idempotencyLog: IdempotencyLog
    artifactStore: ArtifactStore
    freshnessDefaults: dict[str, int] = field(default_factory=dict)
    # Attestation policy. threshold == 0 disables attestation enforcement; when
    # > 0, HIGH-class effects must carry a valid k-of-n upper-bound TimeProof.
    attestationThreshold: int = 0
    maxAttestationWindowMs: Optional[int] = None
    maxAttestationRadiusMs: Optional[int] = None
    # action -> riskClass, part of the SIGNED policy (covered by policy_hash) so
    # the required risk is bound and cannot be downgraded by a boundary's label.
    actionRiskClasses: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# PolicySnapshot (checked on replay only)
# --------------------------------------------------------------------------


def policy_hash(config: VerifierConfig, human_auth: dict, token: dict) -> str:
    snapshot = {
        "permittedActions": sorted(token["permittedActions"]),
        "permittedTargets": sorted(token["permittedTargets"]),
        # riskClass per permitted action is part of the signed policy: a mediator
        # cannot relabel a HIGH action LOW to dodge attestation without breaking
        # the policyHash the auditor recomputes.
        "actionRiskClasses": {a: config.actionRiskClasses.get(a)
                              for a in sorted(token["permittedActions"])},
        "verifierVersion": config.version,
        "clockSkewToleranceMs": config.clockSkewToleranceMs,
        "rootReceiptId": human_auth["receiptId"],
        "tokenId": token["tokenId"],
    }
    return sha256_hex(jcs(snapshot))


# --------------------------------------------------------------------------
# Shared invariant helpers
# --------------------------------------------------------------------------


def _check_key(
    config: VerifierConfig,
    key_id: str,
    expected_owner: str,
    at_time: str,
    revoked_code: str,
    expired_code: str,
    artifact_id: str,
) -> list[ChainVerificationError]:
    errs: list[ChainVerificationError] = []
    rec = config.keyRegistry.get(key_id)
    if rec is None:
        return [ChainVerificationError("UNKNOWN_KEY", f"no key {key_id}", artifact_id)]
    if rec.owner != expected_owner:
        errs.append(
            ChainVerificationError(
                "KEY_OWNER_MISMATCH",
                f"{key_id} owned by {rec.owner!r}, expected {expected_owner!r}",
                artifact_id,
            )
        )
    active, reason = config.keyRegistry.is_active_at(key_id, at_time)
    if not active:
        if reason == "KEY_REVOKED":
            errs.append(ChainVerificationError(revoked_code, f"{key_id} revoked", artifact_id))
        elif reason == "KEY_EXPIRED":
            errs.append(ChainVerificationError(expired_code, f"{key_id} expired", artifact_id))
        elif reason == "KEY_NOT_YET_ACTIVE":
            errs.append(ChainVerificationError("KEY_NOT_YET_ACTIVE", f"{key_id} not yet active", artifact_id))
        else:
            errs.append(ChainVerificationError("UNKNOWN_KEY", f"{key_id} unknown", artifact_id))
    return errs


def _subset(child: list[str], parent: list[str]) -> bool:
    return set(child).issubset(set(parent))


# --------------------------------------------------------------------------
# Issuance-time authorization decision (mediator)
# --------------------------------------------------------------------------


def evaluate_authorization(
    config: VerifierConfig,
    *,
    human_auth: dict,
    token: dict,
    requested_action: str,
    requested_target: str,
    ledger_head: LedgerHeadRef,
    verified_at: str,
    nonce: Optional[str] = None,
    consume_nonce: bool = True,
    consume_usage: bool = True,
    applied_bound: Optional[dict] = None,
    revocation_as_of: Optional[str] = None,
) -> list[ChainVerificationError]:
    """Fail-closed authorization decision. Empty list => PASS (PRE_EFFECT).
    Any error => FAIL (BLOCKED). Side effects (nonce/usage) only run when the
    request is otherwise authorized and the caller asks to consume them."""
    errs: list[ChainVerificationError] = []

    # --- crypto: signatures over both upstream artifacts -------------------
    gov_key = config.keyRegistry.get(human_auth["issuerKeyId"])
    if gov_key is None or not verify_signature(gov_key.publicKeyPem, human_auth):
        errs.append(ChainVerificationError("INVALID_SIGNATURE", "HumanAuthReceipt signature", human_auth["receiptId"]))
    issuer_key = config.keyRegistry.get(token["issuer"]["keyId"])
    if issuer_key is None or not verify_signature(issuer_key.publicKeyPem, token):
        errs.append(ChainVerificationError("INVALID_SIGNATURE", "DelegationToken signature", token["tokenId"]))

    # --- key ownership + lifecycle ----------------------------------------
    errs += _check_key(config, human_auth["issuerKeyId"], GOVERNANCE_OWNER,
                       human_auth["issuedAt"], "ISSUER_KEY_REVOKED", "ISSUER_KEY_EXPIRED", human_auth["receiptId"])
    errs += _check_key(config, token["issuer"]["keyId"], token["issuer"]["agentId"],
                       token["issuedAt"], "ISSUER_KEY_REVOKED", "ISSUER_KEY_EXPIRED", token["tokenId"])
    errs += _check_key(config, token["delegatee"]["keyId"], token["delegatee"]["agentId"],
                       token["issuedAt"], "DELEGATEE_KEY_REVOKED", "DELEGATEE_KEY_EXPIRED", token["tokenId"])

    # --- agent binding -----------------------------------------------------
    if token["issuer"]["agentId"] != human_auth["authorizedAgent"]:
        errs.append(ChainVerificationError("AGENT_MISMATCH", "token issuer != authorizedAgent", token["tokenId"]))

    # --- hash binding root<-token -----------------------------------------
    stored_root_hash = config.artifactStore.get_hash(human_auth["receiptId"])
    if stored_root_hash is None:
        errs.append(ChainVerificationError("ROOT_RECEIPT_NOT_FOUND", human_auth["receiptId"], human_auth["receiptId"]))
    elif token["issuer"]["parentReceiptHash"] != stored_root_hash:
        errs.append(ChainVerificationError("PARENT_HASH_MISMATCH", "token parent hash != stored root", token["tokenId"]))

    # --- scope containment -------------------------------------------------
    if not _subset(token["permittedActions"], human_auth["permittedActions"]) or \
       not _subset(token["permittedTargets"], human_auth["permittedTargets"]):
        errs.append(ChainVerificationError("SCOPE_EXCEEDS_PARENT", "token scope exceeds parent", token["tokenId"]))
    if requested_action not in token["permittedActions"]:
        errs.append(ChainVerificationError("ACTION_NOT_PERMITTED", requested_action, token["tokenId"]))
    if requested_target not in token["permittedTargets"]:
        errs.append(ChainVerificationError("TARGET_NOT_PERMITTED", requested_target, token["tokenId"]))

    # --- expiry ------------------------------------------------------------
    skew = config.clockSkewToleranceMs
    if ms_between(verified_at, human_auth["expiresAt"]) > skew:
        errs.append(ChainVerificationError("ROOT_RECEIPT_EXPIRED", human_auth["receiptId"], human_auth["receiptId"]))
    if ms_between(verified_at, token["expiresAt"]) > skew:
        errs.append(ChainVerificationError("TOKEN_EXPIRED", token["tokenId"], token["tokenId"]))

    # --- revocation (POINT-IN-TIME) ---------------------------------------
    # A revocation takes effect from its revokedAt. Evaluated as of
    # ``revocation_as_of`` -- the issuance-time mediator passes verified_at; the
    # auditor passes the attested upper bound t_ub so the verdict becomes
    # "no revocation effective by t_ub" and self-asserted times cannot dodge it.
    revoke_as_of = revocation_as_of or verified_at
    if config.revocationLog.is_revoked_at(human_auth["receiptId"], revoke_as_of) is not None:
        errs.append(ChainVerificationError("ROOT_RECEIPT_REVOKED", human_auth["receiptId"], human_auth["receiptId"]))
    if config.revocationLog.is_revoked_at(token["tokenId"], revoke_as_of) is not None:
        errs.append(ChainVerificationError("TOKEN_REVOKED", token["tokenId"], token["tokenId"]))

    # --- freshness (invariant 16) -----------------------------------------
    # The applied bound is the per-action-class bound the mediator enforces; it
    # must be no looser than the session token's declared bound.
    bound = applied_bound or token["freshnessBound"]
    if bound["maxAgeMs"] > token["freshnessBound"]["maxAgeMs"]:
        errs.append(ChainVerificationError(
            "FRESHNESS_VIOLATION",
            "applied bound looser than token bound",
            token["tokenId"],
        ))
    age = ms_between(verified_at, ledger_head.capturedAt)
    if age > bound["maxAgeMs"]:
        errs.append(ChainVerificationError(
            "FRESHNESS_VIOLATION",
            f"ledger view {age}ms old > {bound['maxAgeMs']}ms ({bound['riskClass']})",
            token["tokenId"],
        ))

    # --- replay protection + usage (only consume when otherwise authorized)
    if not errs:
        if nonce is not None and consume_nonce:
            if not config.nonceLog.record(nonce, verified_at):
                errs.append(ChainVerificationError("NONCE_ALREADY_SEEN", nonce, token["tokenId"]))
        if not errs and consume_usage:
            max_uses = human_auth.get("maxUses") if human_auth["usagePolicy"] == "MULTI_USE" else 1
            if not config.usageLedger.record(human_auth["receiptId"], max_uses):
                errs.append(ChainVerificationError("USAGE_LIMIT_EXCEEDED", human_auth["receiptId"], human_auth["receiptId"]))

    return errs


# --------------------------------------------------------------------------
# Replay verification (auditor) -- trustless
# --------------------------------------------------------------------------


def verify_chain(
    config: VerifierConfig,
    *,
    human_auth: dict,
    token: dict,
    boundary: dict,
    result: Optional[dict] = None,
    last_sequence: int = -1,
    as_of_now: Optional[str] = None,
) -> ChainVerificationResult:
    """Replay the full chain over stored, signed artifacts. Does not trust the
    mediator's asserted status -- recomputes the authorization outcome.

    Reports two verdicts: ``authorizedAtExecution`` (was the action authorized
    as of its own verifiedAt) and ``authorityLiveNow`` (is the authority still
    live as of ``as_of_now``, default: wall-clock now)."""
    now = as_of_now or now_iso()
    intact_errors: list[ChainVerificationError] = []
    auth_errors: list[ChainVerificationError] = []
    freshness_ok = True
    chain = {
        "humanAuthReceipt": human_auth,
        "delegationToken": token,
        "boundaryReceipt": boundary,
        "executionResultReceipt": result,
    }

    # ---- chainIntact: crypto + ownership + hash bindings + structure ------
    def sig_ok(artifact: dict, key_id: str) -> bool:
        rec = config.keyRegistry.get(key_id)
        return rec is not None and verify_signature(rec.publicKeyPem, artifact)

    for artifact, key_id, aid in (
        (human_auth, human_auth["issuerKeyId"], human_auth["receiptId"]),
        (token, token["issuer"]["keyId"], token["tokenId"]),
        (boundary, boundary["executingAgentKeyId"], boundary["receiptId"]),
    ):
        if not sig_ok(artifact, key_id):
            intact_errors.append(ChainVerificationError("INVALID_SIGNATURE", "bad/unknown signature", aid))

    # ownership
    gov = config.keyRegistry.get(human_auth["issuerKeyId"])
    if gov is None or gov.owner != GOVERNANCE_OWNER:
        intact_errors.append(ChainVerificationError("KEY_OWNER_MISMATCH", "governance key", human_auth["receiptId"]))
    mk = config.keyRegistry.get(boundary["executingAgentKeyId"])
    if mk is None or mk.owner != boundary["executingAgent"]:
        intact_errors.append(ChainVerificationError("KEY_OWNER_MISMATCH", "executing-agent key", boundary["receiptId"]))

    # hash bindings
    if boundary["root"]["receiptHash"] != hash_artifact(human_auth):
        intact_errors.append(ChainVerificationError("PARENT_HASH_MISMATCH", "boundary.root hash", boundary["receiptId"]))
    if boundary["delegation"]["tokenHash"] != hash_artifact(token):
        intact_errors.append(ChainVerificationError("PARENT_HASH_MISMATCH", "boundary.delegation hash", boundary["receiptId"]))
    if boundary["root"]["receiptId"] != token["issuer"]["parentReceiptId"]:
        intact_errors.append(ChainVerificationError("CHAIN_INTEGRITY_VIOLATION", "root id mismatch", boundary["receiptId"]))
    if boundary["executingAgent"] != token["delegatee"]["agentId"]:
        intact_errors.append(ChainVerificationError("AGENT_MISMATCH", "executingAgent != delegatee", boundary["receiptId"]))

    # boundary status/verification consistency
    status, vresult = boundary["status"], boundary["verification"]["result"]
    if (status == "PRE_EFFECT") != (vresult == "PASS") or (status == "BLOCKED") != (vresult == "FAIL"):
        intact_errors.append(ChainVerificationError("MALFORMED_ARTIFACT", f"status {status} vs result {vresult}", boundary["receiptId"]))

    # policyHash (replay-only)
    expected_policy = policy_hash(config, human_auth, token)
    if boundary["verification"].get("policyHash") != expected_policy:
        intact_errors.append(ChainVerificationError("POLICY_NOT_FOUND", "policyHash mismatch on replay", boundary["receiptId"]))

    # ---- freshnessSatisfied: independent recomputation --------------------
    head = boundary["verification"]["ledgerHead"]
    bound = boundary["verification"]["freshnessBound"]

    # The freshness guarantee rests on the AUTHORITY having stamped capturedAt.
    # Verify the revocation service's signature over the head BEFORE trusting
    # capturedAt -- otherwise a mediator could forge a fresh capturedAt over a
    # stale head and slip past the age check.
    head_key = config.keyRegistry.get(head.get("keyId"))
    head_signed_ok = (
        head_key is not None
        and head_key.owner == REVOCATION_SERVICE_OWNER
        and verify_signature(head_key.publicKeyPem, {
            "sequenceNumber": head["sequenceNumber"],
            "headHash": head["headHash"],
            "capturedAt": head["capturedAt"],
            "keyId": head["keyId"],
            "signature": head.get("signature"),
        })
    )
    if not head_signed_ok:
        freshness_ok = False
        auth_errors.append(ChainVerificationError(
            "FRESHNESS_VIOLATION", "ledger head not authority-signed (or tampered)", boundary["receiptId"]))

    age = ms_between(boundary["verification"]["verifiedAt"], head["capturedAt"])
    if age > bound["maxAgeMs"]:
        freshness_ok = False
        auth_errors.append(ChainVerificationError("FRESHNESS_VIOLATION", f"{age}ms > {bound['maxAgeMs']}ms", boundary["receiptId"]))
    if head["sequenceNumber"] < last_sequence:
        freshness_ok = False
        auth_errors.append(ChainVerificationError("FRESHNESS_VIOLATION", "ledger sequence regression (rollback)", boundary["receiptId"]))

    # ---- attested-clock anchoring (closes backdating of EVERY timestamp) ---
    # For a HIGH-class effect, the ExecutionResultReceipt must carry a valid
    # k-of-n upper-bound TimeProof. Its t_ub is a provable upper bound on the
    # true completion time (the authorities stamp an honest midpoint), so a
    # mediator that backdates all self-asserted timestamps cannot pull the
    # action's effective instant earlier than the honest clock. We re-key both
    # the revocation eval and the stale-head cross-check to this attested t_ub.
    verified_at_iso = boundary["verification"]["verifiedAt"]
    completed_at_iso = result["completedAt"] if result is not None else verified_at_iso
    # Required risk comes from the SIGNED policy, by action -- NOT from the
    # boundary's asserted freshnessBound.riskClass, which a mediator could
    # downgrade to skip attestation.
    required_risk = config.actionRiskClasses.get(boundary["requestedAction"])
    attested_t_ub: Optional[str] = None

    if config.attestationThreshold > 0 and required_risk == "HIGH" \
            and status == "PRE_EFFECT" and result is not None:
        # HIGH effects must carry an unpredictable post-effect token.
        if not result.get("effectRef"):
            auth_errors.append(ChainVerificationError(
                ATTESTATION_MISSING, "HIGH effect missing unpredictable effectRef", result["receiptId"]))
        up = result.get("timeProof")
        if up is None:
            auth_errors.append(ChainVerificationError(
                ATTESTATION_MISSING, "HIGH effect lacks an upper-bound time proof", result["receiptId"]))
        else:
            up_errs = verify_time_proof(
                up, expected_nonce=result_proof_nonce(result),
                key_registry=config.keyRegistry, threshold=config.attestationThreshold,
                max_radius_ms=config.maxAttestationRadiusMs)
            auth_errors += [ChainVerificationError(c, "upper-bound proof", result["receiptId"]) for c in up_errs]
            if not up_errs:
                attested_t_ub = up["midpoint"]
                attested_t_ub = add_ms(attested_t_ub, up["radius_ms"])  # t_ub = midpoint + radius

            # Optional lower-bound proof feeds t_lb + the window cap (hardening).
            lo = boundary["verification"].get("lowerBoundProof")
            if lo is not None:
                lo_errs = verify_time_proof(
                    lo, expected_nonce=boundary["nonce"],
                    key_registry=config.keyRegistry, threshold=config.attestationThreshold,
                    max_radius_ms=config.maxAttestationRadiusMs)
                auth_errors += [ChainVerificationError(c, "lower-bound proof", boundary["receiptId"]) for c in lo_errs]
                if not lo_errs and attested_t_ub is not None:
                    t_lb = add_ms(lo["midpoint"], -lo["radius_ms"])
                    cap = boundary["verification"].get("maxAttestationWindowMs", config.maxAttestationWindowMs)
                    if cap is not None and ms_between(attested_t_ub, t_lb) > cap:
                        auth_errors.append(ChainVerificationError(
                            ATTESTATION_WINDOW_EXCEEDED,
                            f"attestation window {ms_between(attested_t_ub, t_lb)}ms > {cap}ms",
                            boundary["receiptId"]))
                    # Interval consistency: t_lb <= verifiedAt <= completedAt <= t_ub.
                    if not (ms_between(verified_at_iso, t_lb) >= 0
                            and ms_between(completed_at_iso, verified_at_iso) >= 0
                            and ms_between(attested_t_ub, completed_at_iso) >= 0):
                        auth_errors.append(ChainVerificationError(
                            ATTESTATION_INTERVAL_INCONSISTENT,
                            "self-asserted times fall outside the attested interval",
                            result["receiptId"]))

    # The effective instant for revocation: the attested upper bound when we
    # have one, else the self-asserted completion (non-HIGH / no attestation).
    effective_instant = attested_t_ub or completed_at_iso

    # ---- stale-head vs. KNOWN revocation (closes the backdating seam) ------
    # An authentically-signed head can still be a PRE-revocation head that a
    # mediator quotes while backdating verifiedAt so the age check passes. Tie
    # the quoted head to the action's effective instant (attested t_ub when
    # present): for every revocation known to be effective by then, the head
    # must have been captured at/after the revokedAt AND quote a sequenceNumber
    # >= that revocation's sequence.
    action_instant = effective_instant
    for entry in config.revocationLog.all_entries():
        if ms_between(action_instant, entry.revokedAt) < 0:
            continue  # revocation not yet effective by the action's completion
        stale_time = ms_between(head["capturedAt"], entry.revokedAt) < 0
        stale_seq = entry.sequence is not None and head["sequenceNumber"] < entry.sequence
        if stale_time or stale_seq:
            freshness_ok = False
            auth_errors.append(ChainVerificationError(
                STALE_HEAD_VS_KNOWN_REVOCATION,
                f"head (capturedAt={head['capturedAt']}, seq={head['sequenceNumber']}) "
                f"predates revocation {entry.artifactId} effective {entry.revokedAt} "
                f"(seq {entry.sequence}) by action completion {action_instant}",
                boundary["receiptId"],
            ))

    # ---- valid: recomputed authorization outcome (trustless) --------------
    recomputed = evaluate_authorization(
        config,
        human_auth=human_auth,
        token=token,
        requested_action=boundary["requestedAction"],
        requested_target=boundary["requestedTarget"],
        ledger_head=LedgerHeadRef(head["sequenceNumber"], head["headHash"], head["capturedAt"]),
        verified_at=boundary["verification"]["verifiedAt"],
        nonce=None,            # replay: never consume ledgers
        consume_nonce=False,
        consume_usage=False,
        applied_bound=bound,   # recompute against the bound the receipt recorded
        revocation_as_of=effective_instant,   # attested t_ub when available
    )
    auth_errors += recomputed

    recomputed_decision = "BLOCKED" if recomputed else "PRE_EFFECT"
    if recomputed_decision != status:
        # The mediator asserted a status the ledgers do not support -> caught.
        auth_errors.append(ChainVerificationError(
            "CHAIN_INTEGRITY_VIOLATION",
            f"mediator asserted {status} but ledgers imply {recomputed_decision}",
            boundary["receiptId"],
        ))

    # ---- ExecutionResultReceipt invariants (if present) -------------------
    if result is not None:
        rk = config.keyRegistry.get(result["executingAgentKeyId"])
        if rk is None or not verify_signature(rk.publicKeyPem, result):
            intact_errors.append(ChainVerificationError("INVALID_SIGNATURE", "result signature", result["receiptId"]))
        if status == "BLOCKED":
            auth_errors.append(ChainVerificationError("RESULT_FOR_BLOCKED_BOUNDARY", "result over blocked boundary", result["receiptId"]))
        elif status != "PRE_EFFECT":
            auth_errors.append(ChainVerificationError("RESULT_WITHOUT_VALID_BOUNDARY", "no valid boundary", result["receiptId"]))
        if result["boundaryReceiptHash"] != hash_artifact(boundary):
            intact_errors.append(ChainVerificationError("PARENT_HASH_MISMATCH", "result->boundary hash", result["receiptId"]))
        obs = result["observedRequest"]
        if (obs["action"] != boundary["requestedAction"]
                or obs["target"] != boundary["requestedTarget"]
                or obs["payloadHash"] != boundary["payloadHash"]):
            intact_errors.append(ChainVerificationError("OBSERVED_REQUEST_MISMATCH", "result != boundary", result["receiptId"]))
        if ms_between(result["completedAt"], boundary["issuedAt"]) < 0:
            auth_errors.append(ChainVerificationError("TIMING_VIOLATION", "completedAt < boundary issuedAt", result["receiptId"]))

    chain_intact = not intact_errors
    # Point-in-time: authorized as of the action's own verifiedAt.
    authorized_at_execution = chain_intact and not auth_errors and status == "PRE_EFFECT"
    # Present: is the authority still live right now? Independent of whether the
    # past action was authorized -- a later revocation flips this without making
    # the executed action read as never-authorized.
    authority_live_now = (
        config.revocationLog.is_revoked_at(human_auth["receiptId"], now) is None
        and config.revocationLog.is_revoked_at(token["tokenId"], now) is None
    )
    return ChainVerificationResult(
        valid=authorized_at_execution,
        chainIntact=chain_intact,
        freshnessSatisfied=freshness_ok,
        authorizedAtExecution=authorized_at_execution,
        authorityLiveNow=authority_live_now,
        errors=intact_errors + auth_errors,
        chain=chain,
    )
