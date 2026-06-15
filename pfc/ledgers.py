"""Mutable state lives in ledgers only (pfc-delegation-chain Core Rule).

  * KeyRegistry    -- keys bound to owners; isActiveAt() for all lifecycle checks.
  * RevocationLog  -- RETROACTIVE artifact revocation; also exposes a monotonic
                      ledger head (sequenceNumber/headHash/capturedAt) so the
                      verifier can enforce freshness and detect rollback.
  * UsageLedger    -- atomic check-and-increment.
  * NonceLog       -- atomic check-and-insert.
  * IdempotencyLog -- atomic check-and-insert (NEW / SAFE_RETRY / CONFLICT).
  * ArtifactStore  -- append-only; put* throws on failure; getHash() = SHA-256/JCS.

The RevocationLog is the part that matters for the "authority gap" demo: it is
the live authority view the PFC mediator re-consults on every request. The
OAuth-stateless server in vulnerable/ has no equivalent it ever reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import hash_artifact, now_iso, parse_iso, sha256_hex

# --------------------------------------------------------------------------
# KeyRegistry
# --------------------------------------------------------------------------


@dataclass
class KeyRecord:
    keyId: str
    owner: str
    publicKeyPem: str
    registeredAt: str
    expiresAt: str
    revokedAt: Optional[str] = None


class KeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}

    def register(self, record: KeyRecord) -> None:
        self._keys[record.keyId] = record

    def get(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)

    def all_records(self) -> list:
        return list(self._keys.values())

    def is_active_at(self, key_id: str, timestamp: str) -> tuple[bool, Optional[str]]:
        """registeredAt <= T, expiresAt > T, revokedAt undefined or > T.
        Key revocation is NON-RETROACTIVE: old receipts stay verifiable."""
        rec = self._keys.get(key_id)
        if rec is None:
            return False, "UNKNOWN_KEY"
        t = parse_iso(timestamp)
        if parse_iso(rec.registeredAt) > t:
            return False, "KEY_NOT_YET_ACTIVE"
        if parse_iso(rec.expiresAt) <= t:
            return False, "KEY_EXPIRED"
        if rec.revokedAt is not None and parse_iso(rec.revokedAt) <= t:
            return False, "KEY_REVOKED"
        return True, None


# --------------------------------------------------------------------------
# RevocationLog (+ ledger head for freshness)
# --------------------------------------------------------------------------


@dataclass
class RevocationEntry:
    artifactId: str
    revokedAt: str
    reason: str
    revokedBy: str
    # Ledger sequence number assigned when the revocation was recorded. Set by
    # RevocationLog.revoke(); a head that postdates this revocation must quote a
    # sequenceNumber >= this value.
    sequence: Optional[int] = None


# The owner an authority-signed ledger head must be bound to in the KeyRegistry.
REVOCATION_SERVICE_OWNER = "revocation-service"


@dataclass
class LedgerHeadRef:
    """The authority's attested view of the revocation-ledger head.

    The triple {sequenceNumber, headHash, capturedAt} -- together with the
    signing key id -- is signed by the revocation service. ``capturedAt`` is
    therefore stamped by the authority, not by whoever later quotes the head,
    so a mediator cannot forge a fresher ``capturedAt`` to dodge a freshness
    bound without invalidating the signature."""

    sequenceNumber: int
    headHash: str
    capturedAt: str
    keyId: Optional[str] = None
    signature: Optional[str] = None

    def signing_body(self) -> dict:
        return {
            "sequenceNumber": self.sequenceNumber,
            "headHash": self.headHash,
            "capturedAt": self.capturedAt,
            "keyId": self.keyId,
        }

    def as_dict(self) -> dict:
        d = self.signing_body()
        d["signature"] = self.signature
        return d


class RevocationLog:
    """Append-only revocation ledger that also publishes an authority-signed
    head. Point-in-time semantics: a revocation takes effect from its
    ``revokedAt`` -- an action that executed strictly before that instant
    remains authorized-at-execution, while a later check sees the revocation."""

    def __init__(self, signing_key=None, key_id: Optional[str] = None) -> None:
        self._entries: dict[str, RevocationEntry] = {}
        self._seq = 0
        self._head_hash = sha256_hex(b"genesis")
        self._signing_key = signing_key       # revocation-service KeyPair
        self._key_id = key_id

    def revoke(self, entry: RevocationEntry) -> None:
        self._seq += 1
        if entry.sequence is None:
            entry.sequence = self._seq
        self._entries[entry.artifactId] = entry
        self._head_hash = sha256_hex(
            (self._head_hash + entry.artifactId + entry.revokedAt).encode("utf-8")
        )

    def is_revoked(self, artifact_id: str) -> Optional[RevocationEntry]:
        """Diagnostic: any revocation regardless of time."""
        return self._entries.get(artifact_id)

    def all_entries(self) -> list:
        """All revocation entries (read-only snapshot) for cross-checks."""
        return list(self._entries.values())

    def is_revoked_at(self, artifact_id: str, as_of: str) -> Optional[RevocationEntry]:
        """Point-in-time: revoked iff a revocation exists with revokedAt <= as_of."""
        entry = self._entries.get(artifact_id)
        if entry is not None and parse_iso(entry.revokedAt) <= parse_iso(as_of):
            return entry
        return None

    def head(self, captured_at: Optional[str] = None) -> LedgerHeadRef:
        """The authority's signed view of the ledger head at capture time. The
        mediator must obtain this fresh on every request; it cannot mint or
        alter it because it does not hold the revocation-service key."""
        ref = LedgerHeadRef(
            sequenceNumber=self._seq,
            headHash=self._head_hash,
            capturedAt=captured_at or now_iso(),
            keyId=self._key_id,
        )
        if self._signing_key is not None:
            ref.signature = self._signing_key.sign_body(ref.signing_body())
        return ref


# --------------------------------------------------------------------------
# UsageLedger / NonceLog / IdempotencyLog
# --------------------------------------------------------------------------


class UsageLedger:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def record(self, receipt_id: str, max_uses: Optional[int]) -> bool:
        """Atomic check-and-increment. Pass max_uses=1 for SINGLE_USE.
        Returns False if the limit would be exceeded."""
        current = self._counts.get(receipt_id, 0)
        if max_uses is not None and current + 1 > max_uses:
            return False
        self._counts[receipt_id] = current + 1
        return True

    def count_for(self, receipt_id: str) -> int:
        return self._counts.get(receipt_id, 0)


class NonceLog:
    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def record(self, nonce: str, seen_at: str) -> bool:
        """Atomic check-and-insert. False if nonce already seen."""
        if nonce in self._seen:
            return False
        self._seen[nonce] = seen_at
        return True


class IdempotencyLog:
    def __init__(self) -> None:
        self._records: dict[str, str] = {}

    def record(self, key: str, payload_hash: str) -> str:
        """Same key + same payload = SAFE_RETRY; same key + different payload
        = CONFLICT; otherwise NEW."""
        prior = self._records.get(key)
        if prior is None:
            self._records[key] = payload_hash
            return "NEW"
        return "SAFE_RETRY" if prior == payload_hash else "CONFLICT"


# --------------------------------------------------------------------------
# ArtifactStore (append-only)
# --------------------------------------------------------------------------


class ArtifactStore:
    def __init__(self) -> None:
        self._artifacts: dict[str, dict] = {}
        self._hashes: dict[str, str] = {}

    def _put(self, artifact_id: str, artifact: dict) -> None:
        if artifact_id in self._artifacts:
            raise ValueError(f"append-only store: {artifact_id} already present")
        self._artifacts[artifact_id] = artifact
        self._hashes[artifact_id] = hash_artifact(artifact)

    def put_human_auth_receipt(self, r: dict) -> None:
        self._put(r["receiptId"], r)

    def put_delegation_token(self, t: dict) -> None:
        self._put(t["tokenId"], t)

    def put_boundary_receipt(self, r: dict) -> None:
        self._put(r["receiptId"], r)

    def put_execution_result_receipt(self, r: dict) -> None:
        self._put(r["receiptId"], r)

    def get(self, artifact_id: str) -> Optional[dict]:
        return self._artifacts.get(artifact_id)

    def get_hash(self, artifact_id: str) -> Optional[str]:
        return self._hashes.get(artifact_id)
