"""Standalone chain auditor -- verifies a delegation chain WITHOUT trusting the
mediator that produced it.

The auditor consumes only PUBLIC material:
  * the signed artifacts (HumanAuthReceipt, DelegationToken, BoundaryReceipt,
    and -- if any effect happened -- ExecutionResultReceipt),
  * the KeyRegistry's PUBLIC keys and owners,
  * a snapshot of the RevocationLog.

It never sees a signing key and never asks the mediator whether the chain is
good. It re-verifies every signature, recomputes every hash binding, checks the
PolicySnapshot hash, and -- crucially -- recomputes the authorization decision
from the ledgers and compares it to the status the mediator asserted. A mediator
that stamped PRE_EFFECT on a request whose authority was revoked is caught as a
CHAIN_INTEGRITY_VIOLATION.

A bundle is portable JSON, so the auditor can run on a different host, later,
operated by a different party.

Run:  python -m governed.auditor <bundle.json>
"""

from __future__ import annotations

import json
import sys
from typing import Optional

from pfc import (
    ArtifactStore,
    IdempotencyLog,
    KeyRecord,
    KeyRegistry,
    NonceLog,
    RevocationEntry,
    RevocationLog,
    UsageLedger,
    VerifierConfig,
    now_iso,
    verify_chain,
)
from pfc.verifier import ChainVerificationResult


def build_audit_config(bundle: dict) -> VerifierConfig:
    registry = KeyRegistry()
    for k in bundle["keys"]:
        registry.register(KeyRecord(
            keyId=k["keyId"], owner=k["owner"], publicKeyPem=k["publicKeyPem"],
            registeredAt=k["registeredAt"], expiresAt=k["expiresAt"],
            revokedAt=k.get("revokedAt"),
        ))
    revocation = RevocationLog()
    for r in bundle.get("revocations", []):
        revocation.revoke(RevocationEntry(
            r["artifactId"], r["revokedAt"], r["reason"], r["revokedBy"],
            sequence=r.get("sequence"),    # preserve the original ledger sequence
        ))

    store = ArtifactStore()
    store.put_human_auth_receipt(bundle["humanAuth"])
    store.put_delegation_token(bundle["token"])
    store.put_boundary_receipt(bundle["boundary"])
    if bundle.get("result"):
        store.put_execution_result_receipt(bundle["result"])

    return VerifierConfig(
        version=bundle["verifierVersion"],
        clockSkewToleranceMs=bundle["clockSkewToleranceMs"],
        keyRegistry=registry,
        revocationLog=revocation,
        nonceLog=NonceLog(),
        usageLedger=UsageLedger(),
        idempotencyLog=IdempotencyLog(),
        artifactStore=store,
        attestationThreshold=bundle.get("attestationThreshold", 0),
        maxAttestationWindowMs=bundle.get("maxAttestationWindowMs"),
        maxAttestationRadiusMs=bundle.get("maxAttestationRadiusMs"),
        actionRiskClasses=bundle.get("actionRiskClasses", {}),
    )


ARTIFACT_TIMESTAMP_KEYS = ("issuedAt", "verifiedAt", "completedAt", "startedAt",
                           "capturedAt", "revokedAt")


def max_artifact_timestamp(bundle: dict) -> str:
    """The latest timestamp appearing anywhere in the bundle's artifacts and
    revocation snapshot. Used as the default 'as of' instant for evaluating
    authorityLiveNow when the bundle carries no explicit evaluatedAt."""
    found: list[str] = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ARTIFACT_TIMESTAMP_KEYS and isinstance(v, str):
                    found.append(v)
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    for part in ("humanAuth", "token", "boundary", "result"):
        walk(bundle.get(part))
    walk(bundle.get("revocations"))
    return max(found)


def audit(bundle: dict, last_sequence: int = -1,
          evaluated_at: Optional[str] = None) -> ChainVerificationResult:
    """Replay a bundle. ``authorityLiveNow`` is evaluated as of ``evaluated_at``
    if given, else the bundle's ``evaluatedAt`` field, else wall-clock now."""
    config = build_audit_config(bundle)
    as_of = evaluated_at or bundle.get("evaluatedAt")
    return verify_chain(
        config,
        human_auth=bundle["humanAuth"],
        token=bundle["token"],
        boundary=bundle["boundary"],
        result=bundle.get("result"),
        last_sequence=last_sequence,
        as_of_now=as_of,
    )


def bundle_from_world(world, boundary: dict, result: Optional[dict]) -> dict:
    """Serialize a portable audit bundle from a World, using PUBLIC keys and a
    revocation snapshot only -- no signing keys leave the mediator."""
    keys = []
    for rec in world.key_registry.all_records():     # gov, agent A, mediator, rev, all time authorities
        keys.append({
            "keyId": rec.keyId, "owner": rec.owner, "publicKeyPem": rec.publicKeyPem,
            "registeredAt": rec.registeredAt, "expiresAt": rec.expiresAt,
            "revokedAt": rec.revokedAt,
        })
    revocations = [
        {"artifactId": e.artifactId, "revokedAt": e.revokedAt, "reason": e.reason,
         "revokedBy": e.revokedBy, "sequence": e.sequence}
        for e in world.revocation_log.all_entries()
    ]
    return {
        "verifierVersion": world.config.version,
        "clockSkewToleranceMs": world.config.clockSkewToleranceMs,
        "attestationThreshold": world.config.attestationThreshold,
        "maxAttestationWindowMs": world.config.maxAttestationWindowMs,
        "maxAttestationRadiusMs": world.config.maxAttestationRadiusMs,
        "actionRiskClasses": dict(world.config.actionRiskClasses),
        # The instant authorityLiveNow is evaluated as of. Defaulted to the
        # bundle-creation time; an auditor may override it (e.g. to ask "was the
        # authority live as of date X?").
        "evaluatedAt": now_iso(),
        "keys": keys,
        "revocations": revocations,
        "humanAuth": world.human_auth,
        "token": world.token,
        "boundary": boundary,
        "result": result,
    }


def _print(res: ChainVerificationResult, evaluated_at: str) -> None:
    print("  chainIntact          :", res.chainIntact)
    print("  freshnessSatisfied   :", res.freshnessSatisfied)
    print("  authorizedAtExecution:", res.authorizedAtExecution)
    print(f"  authorityLiveNow     : {res.authorityLiveNow}  (as of {evaluated_at})")
    print("  errors               :", res.codes() or "(none)")


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: python -m governed.auditor <bundle.json> [evaluatedAt-ISO]")
        return 2
    with open(sys.argv[1]) as fh:
        bundle = json.load(fh)
    # evaluatedAt precedence: CLI arg > bundle field > max artifact timestamp.
    evaluated_at = (sys.argv[2] if len(sys.argv) == 3 else None) \
        or bundle.get("evaluatedAt") or max_artifact_timestamp(bundle)
    res = audit(bundle, evaluated_at=evaluated_at)
    print("=" * 70)
    print("INDEPENDENT AUDIT (mediator not trusted)")
    print("=" * 70)
    _print(res, evaluated_at)
    # An auditor's job is to confirm the chain is cryptographically sound and
    # that its verdict matches the ledgers. A correctly-blocked chain is a
    # PASS for the auditor (intact + verdict consistent), even though valid=False.
    ok = res.chainIntact
    print("\n  audit:", "PASS -- chain is sound and self-consistent" if ok
          else "FAIL -- chain is cryptographically broken")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
