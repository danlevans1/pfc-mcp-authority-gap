"""Build the governed world: keys, registry, the HumanAuthReceipt and
DelegationToken (the chain root and per-session grant), ledgers, the mediator,
and the runtime. The governance ceremony and Agent A's token issuance are
modelled here; from then on the mediator (Agent B) is the only signer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pfc import (
    ActionMapping,
    ArtifactStore,
    FreshnessBound,
    IdempotencyLog,
    KeyPair,
    KeyRecord,
    KeyRegistry,
    Mediator,
    MockRoughtimeQuorum,
    NonceLog,
    RevocationLog,
    TIME_AUTHORITY_OWNER,
    UsageLedger,
    VerifierConfig,
    hash_artifact,
    make_delegation_token,
    make_human_auth_receipt,
)
from pfc.crypto import iso
from pfc.ledgers import REVOCATION_SERVICE_OWNER

# Attested-clock quorum: N independent time authorities, k-of-n.
N_TIME_AUTHORITIES = 5
TIME_QUORUM_THRESHOLD = 3
MAX_ATTESTATION_WINDOW_MS = 5_000
ATTESTATION_RADIUS_MS = 250
MAX_ATTESTATION_RADIUS_MS = 60_000     # reject absurdly-wide / negative radii

from .adapters import CrmResourceAdapter
from .runtime import AgentRuntime, DELETE_CONTACT, HANDOFF, READ_CONTACT

T0 = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

GOVERNANCE = "governance-layer"
AGENT_A = "agent:issuer"          # received the HumanAuthReceipt, issues tokens
MEDIATOR = "agent:crm-mediator"   # Agent B / executingAgent / enforcement point

PERMITTED_ACTIONS = ["manage_crm_objects.delete", "manage_crm_objects.read"]
PERMITTED_TARGETS = ["crm:manage_crm_objects"]

FRESHNESS = {
    "HIGH": FreshnessBound(30_000, "HIGH"),       # 30s: deletes
    "MEDIUM": FreshnessBound(300_000, "MEDIUM"),
    "LOW": FreshnessBound(3_600_000, "LOW"),      # session ceiling (reads)
}

MAPPING = {
    DELETE_CONTACT: ActionMapping("crm", "manage_crm_objects", "delete", "HIGH"),
    READ_CONTACT: ActionMapping("crm", "manage_crm_objects", "read", "LOW"),
    HANDOFF: ActionMapping("", "", "", "LOW", no_effect=True),
}


class MutableClock:
    """A controllable clock so the demo and tests can advance time
    deterministically without sleeping."""

    def __init__(self, base: datetime):
        self._t = base

    def set_seconds_from_base(self, base: datetime, seconds: int) -> None:
        self._t = base + timedelta(seconds=seconds)

    def advance(self, seconds: int) -> None:
        self._t = self._t + timedelta(seconds=seconds)

    def iso(self) -> str:
        return iso(self._t)


@dataclass
class World:
    config: VerifierConfig
    mediator: Mediator
    runtime: AgentRuntime
    human_auth: dict
    token: dict
    key_registry: KeyRegistry
    revocation_log: RevocationLog
    adapter: CrmResourceAdapter
    clock: MutableClock
    quorum: MockRoughtimeQuorum
    time_authority_ids: list
    quorum_clock: MutableClock          # the time authority's OWN clock (independent)


def build_world() -> World:
    gov_key, a_key, b_key = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    rev_key = KeyPair.generate()           # revocation-service: signs ledger heads
    registry = KeyRegistry()
    reg_at = iso(T0 - timedelta(days=1))
    exp_at = iso(T0 + timedelta(days=365))
    registry.register(KeyRecord("gov-key", GOVERNANCE, gov_key.public_pem, reg_at, exp_at))
    registry.register(KeyRecord("a-key", AGENT_A, a_key.public_pem, reg_at, exp_at))
    registry.register(KeyRecord("b-key", MEDIATOR, b_key.public_pem, reg_at, exp_at))
    registry.register(KeyRecord("rev-key", REVOCATION_SERVICE_OWNER, rev_key.public_pem, reg_at, exp_at))

    # Independent time authorities for the attested-clock quorum. The quorum
    # owns its OWN clock, separate from the mediator's -- a malicious mediator
    # cannot move t_ub by lying about its own clock.
    ta_keys = {}
    for i in range(N_TIME_AUTHORITIES):
        kid = f"ta-key-{i}"
        kp = KeyPair.generate()
        ta_keys[kid] = kp
        registry.register(KeyRecord(kid, TIME_AUTHORITY_OWNER, kp.public_pem, reg_at, exp_at))
    quorum_clock = MutableClock(T0)
    quorum = MockRoughtimeQuorum(ta_keys, threshold=TIME_QUORUM_THRESHOLD,
                                 clock=quorum_clock.iso, radius_ms=ATTESTATION_RADIUS_MS)

    store = ArtifactStore()
    # The revocation service holds rev-key and signs every published head; the
    # mediator never holds it, so it cannot forge a head's capturedAt.
    revocation = RevocationLog(signing_key=rev_key, key_id="rev-key")
    config = VerifierConfig(
        version="pfc-0.13-demo",
        clockSkewToleranceMs=5_000,
        keyRegistry=registry,
        revocationLog=revocation,
        nonceLog=NonceLog(),
        usageLedger=UsageLedger(),
        idempotencyLog=IdempotencyLog(),
        artifactStore=store,
        freshnessDefaults={k: v.maxAgeMs for k, v in FRESHNESS.items()},
        attestationThreshold=TIME_QUORUM_THRESHOLD,
        maxAttestationWindowMs=MAX_ATTESTATION_WINDOW_MS,
        maxAttestationRadiusMs=MAX_ATTESTATION_RADIUS_MS,
        actionRiskClasses={f"{m.tool}.{m.operation}": m.risk
                           for m in MAPPING.values() if not m.no_effect},
    )

    # --- governance ceremony: HumanAuthReceipt -------------------------
    human_auth = make_human_auth_receipt(
        receipt_id="har-1",
        authorized_agent=AGENT_A,
        granted_by="user:dana(admin)",
        authority_issued_at=iso(T0),
        permitted_actions=PERMITTED_ACTIONS,
        permitted_targets=PERMITTED_TARGETS,
        usage_policy="MULTI_USE",
        issued_at=iso(T0),
        expires_at=iso(T0 + timedelta(days=1)),
        issuer_key_id="gov-key",
        governance_key=gov_key,
    )
    store.put_human_auth_receipt(human_auth)

    # --- Agent A issues the per-session DelegationToken ----------------
    token = make_delegation_token(
        token_id="dt-1",
        issuer_agent_id=AGENT_A,
        issuer_key_id="a-key",
        parent_receipt_id="har-1",
        parent_receipt_hash=hash_artifact(human_auth),
        delegatee_agent_id=MEDIATOR,
        delegatee_key_id="b-key",
        permitted_actions=PERMITTED_ACTIONS,
        permitted_targets=PERMITTED_TARGETS,
        freshness_bound=FRESHNESS["LOW"],   # session ceiling; actions tighten it
        issued_at=iso(T0),
        expires_at=iso(T0 + timedelta(days=1)),
        issuer_key=a_key,
    )
    store.put_delegation_token(token)

    clock = MutableClock(T0)
    adapter = CrmResourceAdapter()
    mediator = Mediator(
        config=config,
        agent_id=MEDIATOR,
        key=b_key,
        key_id="b-key",
        mapping=MAPPING,
        resource_adapters=[adapter],
        freshness_bounds=FRESHNESS,
        clock=clock.iso,
        quorum=quorum,
        max_attestation_window_ms=MAX_ATTESTATION_WINDOW_MS,
    )
    runtime = AgentRuntime(mediator=mediator, human_auth=human_auth, token=token)
    return World(config, mediator, runtime, human_auth, token, registry,
                 revocation, adapter, clock, quorum, list(ta_keys), quorum_clock)
