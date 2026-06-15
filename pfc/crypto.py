"""Cryptographic primitives for the PFC delegation chain.

Faithful to the pfc-delegation-chain skill's Core Rules:

  * Signing  -- Ed25519 over the JCS-canonicalized (RFC 8785) artifact body
    with the ``signature`` field excluded before serialization.
  * Encoding -- hex.
  * Hashing  -- SHA-256 over the JCS canonicalization of the *signed* artifact.

The JCS implementation here is the lexicographically-sorted-keys / no-whitespace
subset of RFC 8785. Our artifacts only contain strings, integers and nested
objects/arrays, so the floating-point serialization rules of full JCS never
apply -- this subset is canonical for every artifact in this repo.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

# --------------------------------------------------------------------------
# JCS canonicalization + hashing
# --------------------------------------------------------------------------


def _strip_none(value: Any) -> Any:
    """Drop keys whose value is None so absent optional fields (maxUses,
    idempotencyKey, ...) never appear in the canonical form."""
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none(v) for v in value]
    return value


def jcs(obj: Any) -> bytes:
    """RFC 8785 (subset) canonical JSON: sorted keys, no insignificant
    whitespace, UTF-8."""
    return json.dumps(
        _strip_none(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_artifact(artifact: dict) -> str:
    """SHA-256/JCS of the stored (signed) artifact -- the value ArtifactStore
    exposes via getHash()."""
    return sha256_hex(jcs(artifact))


# --------------------------------------------------------------------------
# Ed25519 keys
# --------------------------------------------------------------------------


class KeyPair:
    """An Ed25519 keypair. Public key is exported as PEM for the KeyRegistry;
    that is the only thing a verifier or auditor ever needs."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self._pk = private_key.public_key()

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_pem(self) -> str:
        return self._pk.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def sign_body(self, body: dict) -> str:
        """Sign the JCS canonicalization of an artifact body that does NOT yet
        contain a signature field. Returns a hex signature."""
        if "signature" in body and body["signature"] is not None:
            raise ValueError("body must not contain a signature before signing")
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        return self._sk.sign(jcs(unsigned)).hex()


def verify_signature(public_pem: str, signed_artifact: dict) -> bool:
    """Verify an artifact's hex signature over JCS(body without signature)."""
    sig_hex = signed_artifact.get("signature")
    if not sig_hex:
        return False
    body = {k: v for k, v in signed_artifact.items() if k != "signature"}
    try:
        pk = _load_public_pem(public_pem)
        pk.verify(bytes.fromhex(sig_hex), jcs(body))
        return True
    except (InvalidSignature, ValueError):
        return False


def _load_public_pem(pem: str) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


# --------------------------------------------------------------------------
# Time helpers (UTC ISO-8601; freshness math in milliseconds)
# --------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def ms_between(later_iso: str, earlier_iso: str) -> int:
    delta = parse_iso(later_iso) - parse_iso(earlier_iso)
    return int(delta.total_seconds() * 1000)


def add_ms(base_iso: str, delta_ms: int) -> str:
    """Return base_iso shifted by delta_ms milliseconds (may be negative)."""
    return iso(parse_iso(base_iso) + timedelta(milliseconds=delta_ms))
