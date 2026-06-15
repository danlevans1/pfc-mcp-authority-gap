"""Attested-clock anchoring -- a Roughtime-style time authority that lets the
auditor put a *provable* upper bound on when an effect occurred, independent of
any timestamp the (untrusted) mediator wrote into the chain.

Why this exists
---------------
The stale-head cross-check (see verifier.py) closes backdating only as long as
ONE timestamp in the chain is honest. A mediator that backdates *every*
self-asserted timestamp -- verifiedAt, issuedAt, completedAt -- and quotes a
genuinely pre-revocation signed head produces an internally consistent chain
that no amount of cross-checking against self-asserted fields can distinguish
from a real past action. The only way out is an external, unforgeable clock.

The load-bearing primitive
---------------------------
An **upper-bound proof**: a quorum of independent time authorities sign
``{nonce, midpoint, radius}`` where ``nonce = H(ExecutionResultReceipt content)``.
Because the nonce can only be computed *after* the result exists, obtaining the
proof necessarily happens after the effect, and the authorities stamp their own
honest ``midpoint``. The conservative upper bound is::

    t_ub = midpoint + radius

and the effect provably completed at true time <= t_ub. Revocation is then
re-keyed to t_ub: "authorized at execution" becomes "no revocation effective by
t_ub". A backdating mediator cannot make the honest quorum stamp an earlier
midpoint, so a real T0+600 effect yields t_ub ~ T0+600 and a T0+300 revocation
bites.

The **lower-bound proof** (t_lb = midpoint - radius), fed into the
BoundaryReceipt before the effect, is SECONDARY / hardening: together with a
``maxAttestationWindowMs`` cap on ``t_ub - t_lb`` it bounds how loose the
sandwich may be, catching a stale lower bound. It is optional; the upper-bound
proof is what carries the security argument.

Network is stubbed (no real UDP/Roughtime wire); the signing and quorum
*verification* logic is real (Ed25519, k-of-n over distinct authority keys).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import KeyPair, add_ms, jcs, sha256_hex, verify_signature

# Owner that every time-authority key must be bound to in the KeyRegistry.
TIME_AUTHORITY_OWNER = "time-authority"

# Repo-local error codes (beyond the canonical v0.13 ChainVerificationError
# vocabulary, which the pfc-delegation-chain skill owns).
ATTESTATION_MISSING = "ATTESTATION_MISSING"
ATTESTATION_INVALID_SIGNATURE = "ATTESTATION_INVALID_SIGNATURE"
ATTESTATION_QUORUM_NOT_MET = "ATTESTATION_QUORUM_NOT_MET"
ATTESTATION_NONCE_UNBOUND = "ATTESTATION_NONCE_UNBOUND"
ATTESTATION_WINDOW_EXCEEDED = "ATTESTATION_WINDOW_EXCEEDED"
ATTESTATION_INTERVAL_INCONSISTENT = "ATTESTATION_INTERVAL_INCONSISTENT"

# Fields of an ExecutionResultReceipt that the upper-bound proof's nonce binds
# to (everything semantic except the proof itself and the signature). It
# includes ``effectRef`` -- an unpredictable, server-assigned token only known
# AFTER the effect -- so a proof cannot be pre-fetched against a guessed result.
RESULT_NONCE_FIELDS = (
    "artifactType", "receiptId", "boundaryReceiptId", "boundaryReceiptHash",
    "executingAgent", "executingAgentKeyId", "observedRequest", "outcome",
    "resultHash", "effectRef", "startedAt", "completedAt",
)


def result_proof_nonce(result_like: dict) -> str:
    """H(ExecutionResultReceipt content) -- the nonce an upper-bound proof must
    bind to. Computed identically by the mediator (pre-proof) and the auditor
    (over the stored receipt)."""
    body = {k: result_like[k] for k in RESULT_NONCE_FIELDS if k in result_like}
    return sha256_hex(jcs(body))


@dataclass
class TimeProof:
    """A quorum-signed time attestation over {nonce, midpoint, radius_ms}.

    ``signatures`` is a list of {keyId, signature} from independent time
    authorities, all over the SAME triple; k-of-n distinct valid signatures
    constitute a quorum."""

    nonce: str
    midpoint: str          # ISO-8601 UTC, the authorities' stamped time
    radius_ms: int         # uncertainty radius
    signatures: list       # [{"keyId": str, "signature": hex}]

    def signing_body(self) -> dict:
        return {"nonce": self.nonce, "midpoint": self.midpoint, "radius_ms": self.radius_ms}

    def as_dict(self) -> dict:
        return {**self.signing_body(), "signatures": list(self.signatures)}

    def t_ub(self) -> str:
        return add_ms(self.midpoint, +self.radius_ms)

    def t_lb(self) -> str:
        return add_ms(self.midpoint, -self.radius_ms)


class MockRoughtimeQuorum:
    """N independent time authorities with a k-of-n threshold, modelled as a
    SEPARATE principal from the mediator: the quorum owns its own ``clock`` and
    its own ``radius_ms``. ``prove`` stamps ``midpoint = self.clock()`` and the
    quorum's radius -- it accepts NO caller-supplied time. A mediator therefore
    cannot move ``t_ub`` by lying about its own clock; only the (independent)
    time authority decides what time it is. The network round trip is stubbed;
    the signing and k-of-n verification are real."""

    def __init__(self, keypairs: dict, threshold: int, clock, radius_ms: int = 250):
        if threshold < 1 or threshold > len(keypairs):
            raise ValueError("threshold must be in 1..n")
        if radius_ms < 0:
            raise ValueError("radius_ms must be >= 0")
        self._keys = dict(keypairs)         # keyId -> KeyPair
        self.threshold = threshold
        self.clock = clock                  # callable -> ISO; the authority's own clock
        self.radius_ms = radius_ms

    @property
    def key_ids(self) -> list:
        return list(self._keys)

    def prove(self, *, nonce: str, signer_ids: Optional[list] = None,
              corrupt_ids: tuple = ()) -> TimeProof:
        """Produce a TimeProof. The midpoint and radius come from the quorum's
        OWN clock/config -- never the caller. ``signer_ids`` restricts which
        authorities sign (default: all); ``corrupt_ids`` makes named authorities
        emit an invalid signature (to model compromise)."""
        midpoint_iso = self.clock()
        radius_ms = self.radius_ms
        body = {"nonce": nonce, "midpoint": midpoint_iso, "radius_ms": radius_ms}
        sigs = []
        for kid in (signer_ids if signer_ids is not None else self.key_ids):
            sig = self._keys[kid].sign_body(body)
            if kid in corrupt_ids:
                sig = ("f" + sig[1:]) if sig[0] != "f" else ("0" + sig[1:])  # break it
            sigs.append({"keyId": kid, "signature": sig})
        return TimeProof(nonce=nonce, midpoint=midpoint_iso, radius_ms=radius_ms, signatures=sigs)


def verify_time_proof(proof: dict, *, expected_nonce: str, key_registry,
                      threshold: int, max_radius_ms: Optional[int] = None) -> list:
    """Verify a TimeProof dict. Returns a list of repo-local attestation error
    codes (empty == valid). A quorum of >= threshold distinct valid signatures
    from registered time-authority keys is required; a minority of bad/forged
    signatures does not break a met quorum (that is the point of k-of-n). The
    radius must be in [0, max_radius_ms] -- a negative or absurdly wide radius
    is an inconsistent attestation."""
    errors: list = []
    radius = proof.get("radius_ms")
    body = {"nonce": proof["nonce"], "midpoint": proof["midpoint"], "radius_ms": radius}

    if proof["nonce"] != expected_nonce:
        errors.append(ATTESTATION_NONCE_UNBOUND)

    if not isinstance(radius, int) or radius < 0 or (max_radius_ms is not None and radius > max_radius_ms):
        errors.append(ATTESTATION_INTERVAL_INCONSISTENT)

    valid_keys: set = set()
    saw_invalid = False
    for entry in proof.get("signatures", []):
        rec = key_registry.get(entry.get("keyId"))
        if rec is None or rec.owner != TIME_AUTHORITY_OWNER:
            continue  # not an authorized time authority -> ignore
        ok = verify_signature(rec.publicKeyPem, {**body, "signature": entry.get("signature")})
        if ok:
            valid_keys.add(entry["keyId"])
        else:
            saw_invalid = True

    if len(valid_keys) < threshold:
        errors.append(ATTESTATION_QUORUM_NOT_MET)
        if saw_invalid:
            errors.append(ATTESTATION_INVALID_SIGNATURE)
    return errors
