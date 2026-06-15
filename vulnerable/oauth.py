"""A minimal OAuth 2.1 Authorization Server issuing EdDSA bearer JWTs.

This models the 2026-07-28 MCP authorization profile's *stateless* validation
path: access tokens are self-contained JWTs that a resource server verifies
locally with the AS public key (JWKS), with no token-introspection round-trip
on the hot path. That is the property the demo exercises.

The AS *does* support grant revocation and RFC 7662 introspection -- but a
stateless resource server never calls them. The gap is not that revocation is
impossible; it is that nothing on the request path is required to consult it
before the bearer token's own ``exp``.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenExpired(Exception):
    pass


class TokenInvalid(Exception):
    pass


@dataclass
class AuthorizationServer:
    issuer: str = "https://as.example/2026-07-28"
    _sk: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    # grant store: sub -> set(scopes); revoked grants leave this map.
    _grants: dict[str, set] = field(default_factory=dict)
    # jti -> claims, for introspection (the endpoint the stateless RS skips).
    _issued: dict[str, dict] = field(default_factory=dict)
    _revoked_jti: set = field(default_factory=set)

    @property
    def public_pem(self) -> str:
        return self._sk.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    # -- grant lifecycle ---------------------------------------------------

    def grant_authority(self, sub: str, scopes: set) -> None:
        self._grants[sub] = set(scopes)

    def revoke_authority(self, sub: str) -> None:
        """Revoke the underlying grant (and outstanding tokens) at the AS.
        A stateful RS calling introspection would see this immediately; a
        stateless RS will not until the token's own exp."""
        self._grants.pop(sub, None)
        for jti, claims in self._issued.items():
            if claims["sub"] == sub:
                self._revoked_jti.add(jti)

    # -- token issuance ----------------------------------------------------

    def issue_token(self, sub: str, audience: str, scope: str, ttl_seconds: int,
                    now: Optional[int] = None) -> str:
        now = int(now if now is not None else time.time())
        if sub not in self._grants or not set(scope.split()).issubset(self._grants[sub]):
            raise TokenInvalid("scope exceeds granted authority")
        jti = f"jti-{len(self._issued)+1}"
        header = {"alg": "EdDSA", "typ": "at+jwt", "kid": "as-2026-07-28"}
        payload = {
            "iss": self.issuer, "sub": sub, "aud": audience, "scope": scope,
            "iat": now, "exp": now + ttl_seconds, "jti": jti,
        }
        self._issued[jti] = payload
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
        sig = self._sk.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(sig)}"

    # -- RFC 7662 introspection (NOT on the stateless hot path) ------------

    def introspect(self, jti: str) -> dict:
        """Reflects LIVE authority: inactive once revoked, and the ``scope`` it
        returns is the subject's CURRENT granted scope -- not the scope frozen
        into the token at issuance. Note there is no notion of staleness bound
        here: a cached introspection answer carries no declared max-age."""
        if jti in self._revoked_jti or jti not in self._issued:
            return {"active": False}
        claims = self._issued[jti]
        sub = claims["sub"]
        if sub not in self._grants:
            return {"active": False}
        return {
            "active": True,
            "sub": sub,
            "aud": claims["aud"],
            "exp": claims["exp"],
            "jti": jti,
            "scope": " ".join(sorted(self._grants[sub])),
        }


def verify_jwt_stateless(token: str, as_public_pem: str, audience: str,
                         now: Optional[int] = None) -> dict:
    """Local, stateless JWT validation: signature + exp + aud only. This is all
    a stateless resource server does. No introspection, no revocation list."""
    now = int(now if now is not None else time.time())
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError as exc:
        raise TokenInvalid("malformed token") from exc
    pk = load_pem_public_key(as_public_pem.encode("ascii"))
    if not isinstance(pk, Ed25519PublicKey):
        raise TokenInvalid("AS key is not Ed25519")
    try:
        pk.verify(_b64url_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
    except InvalidSignature as exc:
        raise TokenInvalid("bad signature") from exc
    claims = json.loads(_b64url_decode(p_b64))
    if claims.get("aud") != audience:
        raise TokenInvalid("audience mismatch")
    if now >= claims["exp"]:
        raise TokenExpired("token expired")
    return claims
