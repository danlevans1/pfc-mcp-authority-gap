"""A *diligent* stateless-OAuth baseline: same bearer model as ``vulnerable/``,
but it performs RFC 7662 token introspection on every effectful call and issues
short-lived (15-minute) tokens. This closes the revoke-after-issue gap.

It is the strongest baseline that stays within plain OAuth 2.1 + introspection.
``LIMITS.md`` and the tests document what it still cannot do that the PFC
``governed/`` path can: signed action-bound attestation, a per-action-class
freshness object, trustless re-derivation, and defense against silent scope
expansion past an immutable human grant.
"""
