"""Governed timeline: the same flow, fronted by a PFC mediator.

Episode 1 (authority valid): an allowed delete emits the full
  HumanAuthReceipt -> DelegationToken -> BoundaryReceipt(PRE_EFFECT)
  -> ExecutionResultReceipt(SUCCESS) chain, and an independent audit returns
  valid=True.

Episode 2 (authority revoked after token issuance): the same delete is BLOCKED
  before any effect. The mediator emits a signed BoundaryReceipt(BLOCKED) -- the
  attestation of the denial -- and calls no adapter. The independent auditor
  confirms the chain is cryptographically sound (chainIntact=True) and that the
  denial is genuine (valid=False, ROOT_RECEIPT_REVOKED): denies-and-attests.

Run:  python -m governed.demo
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

from pfc import RevocationEntry
from pfc.crypto import iso

from . import auditor
from .setup import T0, build_world


def run(write_bundles_to: str | None = None) -> dict:
    world = build_world()

    # -- Episode 1: authority valid, allowed delete -> full chain ----------
    world.clock.set_seconds_from_base(T0, 0)
    out1 = world.runtime.handle_instruction("delete c-1002")
    bundle1 = auditor.bundle_from_world(world, out1.boundary_receipt, out1.execution_result)
    audit1 = auditor.audit(bundle1)

    # -- authority revoked at T0+300s (point-in-time: effective from revokedAt)
    world.revocation_log.revoke(RevocationEntry(
        artifactId="har-1",
        revokedAt=iso(T0 + timedelta(seconds=300)),
        reason="security incident: admin pulled the agent's authority",
        revokedBy="user:dana(admin)",
    ))

    # Re-audit episode 1 AFTER the revocation. The action ran at T0, before the
    # revokedAt, so it stays authorized-at-execution; only authorityLiveNow flips.
    bundle1_after = auditor.bundle_from_world(world, out1.boundary_receipt, out1.execution_result)
    audit1_after = auditor.audit(bundle1_after)

    # -- Episode 2: T0+600s, same delete -> BLOCKED before any effect ------
    world.clock.set_seconds_from_base(T0, 600)
    out2 = world.runtime.handle_instruction("delete c-1001")
    bundle2 = auditor.bundle_from_world(world, out2.boundary_receipt, out2.execution_result)
    audit2 = auditor.audit(bundle2)

    if write_bundles_to:
        os.makedirs(write_bundles_to, exist_ok=True)
        for name, b in (("episode1_allowed.json", bundle1), ("episode2_blocked.json", bundle2)):
            with open(os.path.join(write_bundles_to, name), "w") as fh:
                json.dump(b, fh, indent=2)

    return {
        "episode1": {
            "status": out1.status,
            "effect_happened": out1.effect_happened,
            "has_execution_result": out1.execution_result is not None,
            "audit_valid": audit1.valid,
            "audit_chain_intact": audit1.chainIntact,
            "audit_codes": audit1.codes(),
        },
        "episode1_after_revocation": {
            "authorized_at_execution": audit1_after.authorizedAtExecution,
            "authority_live_now": audit1_after.authorityLiveNow,
            "chain_intact": audit1_after.chainIntact,
            "audit_codes": audit1_after.codes(),
        },
        "episode2": {
            "status": out2.status,
            "effect_happened": out2.effect_happened,
            "has_execution_result": out2.execution_result is not None,
            "audit_valid": audit2.valid,
            "authorized_at_execution": audit2.authorizedAtExecution,
            "authority_live_now": audit2.authorityLiveNow,
            "audit_chain_intact": audit2.chainIntact,
            "audit_freshness": audit2.freshnessSatisfied,
            "audit_codes": audit2.codes(),
        },
        "contacts_remaining": sorted(world.adapter.contacts),
    }


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    r = run(write_bundles_to=os.path.join(here, "_bundles"))
    print("=" * 70)
    print("GOVERNED PATH  -- same flow behind a PFC mediator")
    print("=" * 70)
    e1, e2 = r["episode1"], r["episode2"]
    print("\nEpisode 1 (authority valid) -- delete c-1002")
    print(f"  boundary status        : {e1['status']}")
    print(f"  effect happened        : {e1['effect_happened']}")
    print(f"  full receipt chain      : ExecutionResultReceipt present = {e1['has_execution_result']}")
    print(f"  independent audit       : valid={e1['audit_valid']} intact={e1['audit_chain_intact']} {e1['audit_codes']}")

    print("\n  >> authority REVOKED at the ledger at T0+300s (effective from revokedAt) <<")

    ea = r["episode1_after_revocation"]
    print("\nEpisode 1 re-audited AFTER revocation -- point-in-time verdict")
    print(f"  authorizedAtExecution  : {ea['authorized_at_execution']}  (ran at T0, before revokedAt)")
    print(f"  authorityLiveNow       : {ea['authority_live_now']}  (authority since pulled)")
    print(f"  -> a past-valid action is NOT retroactively invalid; intact={ea['chain_intact']}")

    print("\nEpisode 2 (authority revoked) -- delete c-1001")
    print(f"  boundary status        : {e2['status']}")
    print(f"  effect happened        : {e2['effect_happened']}")
    print(f"  adapter invoked         : {e2['has_execution_result']}  (no ExecutionResultReceipt)")
    print(f"  independent audit       : authorizedAtExecution={e2['authorized_at_execution']} "
          f"authorityLiveNow={e2['authority_live_now']} intact={e2['audit_chain_intact']} "
          f"fresh={e2['audit_freshness']} {e2['audit_codes']}")
    print(f"\n  contacts remaining     : {r['contacts_remaining']}  (c-1001 survived the revoked request)")
    print("\n  DENIES (fail-closed, no effect) AND ATTESTS (signed BLOCKED receipt,")
    print("  independently verifiable to ROOT_RECEIPT_REVOKED without trusting the mediator).")
    print("\n  Audit bundles written to governed/_bundles/ -- run:")
    print("    python -m governed.auditor governed/_bundles/episode2_blocked.json")


if __name__ == "__main__":
    main()
