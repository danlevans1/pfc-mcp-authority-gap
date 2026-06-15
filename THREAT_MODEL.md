# Threat model — MCP authority gap

## Asset under protection

A consequential, hard-to-reverse tool effect: `manage_crm_objects.delete` on a
CRM record. The security claim is narrow and falsifiable: **a tool effect must
not occur after the authority behind it has been revoked**, and any decision to
allow or deny it must be independently verifiable.

## Principals and trust boundaries

| Principal | Holds | Trusted to… |
|-----------|-------|-------------|
| Human / admin (governance) | the governance signing key | authorize and **revoke** authority |
| Agent A (issuer) | its own key | issue a per-session `DelegationToken` within the granted scope |
| LLM | **nothing** — no key, no credential | only to emit untrusted `ActionRequest`s |
| Mediator (Agent B / enforcement point) | the mediator signing key | map requests, verify the chain, issue receipts — **but not trusted by the auditor** |
| Resource adapter | the CRM credential | execute a *verified* call only |
| Revocation service | the `revocation-service` key | sign every published ledger head `{sequenceNumber, headHash, capturedAt}` with a truthful clock |
| Time-authority quorum | N independent `time-authority` keys (k-of-n) | sign `{nonce, midpoint, radius}` with honest clocks; ≥ k must be honest |
| Auditor | public keys + ledger snapshot | re-derive the verdict from scratch |

Boundaries: the LLM is outside the trust boundary entirely (credential
starvation). The mediator is inside it for *liveness* but **not for
correctness** — the auditor recomputes its verdicts.

**Scope of the "trustless" claim.** The auditor is trustless **given an
authority-signed ledger head and an honest authority clock**. The revocation
service is a trusted signer: it holds `revocation-service`, and the freshness
guarantee reduces to trusting (a) that its key is honest and (b) that the
`capturedAt` it stamps is truthful. PFC bounds *staleness* of an authority-signed
view; it cannot conjure a view the authority never signed, nor catch an authority
that lies about its own clock.

## Attacker model and what stops each move

Columns: `vuln` = `vulnerable/`, `dilig` = `diligent/` (stateless OAuth +
introspection + 15m TTL), `gov` = `governed/` (PFC).

| # | Attacker capability | `vuln` | `dilig` | `gov` control | Invariant / error |
|---|---------------------|--------|---------|---------------|-------------------|
| 1 | Use a valid bearer token after the grant is revoked | **executes** | **blocked** (introspection) | Per-request `RevocationLog` check, evaluated point-in-time at the action's `verifiedAt` | `ROOT_RECEIPT_REVOKED`, fail-closed → `BLOCKED` |
| 2 | Replay a stale "all clear" ledger view to dodge a recent revocation | n/a | **not bounded** (introspection has no staleness bound) | Per-action-class `FreshnessBound`; rollback detection via `sequenceNumber` | `FRESHNESS_VIOLATION` |
| 2b | Forge a fresh `capturedAt` over a stale ledger head | n/a | n/a | Ledger head is authority-signed; auditor verifies the `revocation-service` signature over `{sequenceNumber, headHash, capturedAt, keyId}` | `FRESHNESS_VIOLATION` |
| 2c | Backdate `verifiedAt` and quote an **authentic** pre-revocation head | n/a | n/a | Cross-check the quoted head against the revocation snapshot at the action's completion time: for any revocation effective by `completedAt`, require `capturedAt >= revokedAt` and `sequenceNumber >= ` that revocation's sequence | `STALE_HEAD_VS_KNOWN_REVOCATION` |
| 2d | Backdate **every** self-asserted timestamp (`verifiedAt`, `issuedAt`, `completedAt`) and quote a real pre-revocation head | n/a | n/a | **Attested clock**, closed only by TWO independent properties together: (i) the time authority is a **separate principal** that stamps its OWN clock and radius — `prove()` ignores any caller time, so the mediator cannot move `t_ub` by lying about its own clock; and (ii) the upper-bound proof's nonce binds an **unpredictable post-effect token** `effectRef` (∈ `H(ExecutionResultReceipt)`), so the proof cannot be pre-fetched at T0 against a guessed result. `t_ub = midpoint + radius` is then a provable upper bound on completion, and revocation is re-keyed to it | `ROOT_RECEIPT_REVOKED` (effective by `t_ub`); proof faults: `ATTESTATION_MISSING` / `_NONCE_UNBOUND` / `_QUORUM_NOT_MET` / `_INVALID_SIGNATURE` / `_WINDOW_EXCEEDED` / `_INTERVAL_INCONSISTENT` |
| 3 | Widen scope / redirect target at request time | scope fixed in token | scope fixed in token | Target bound at issuance, not from LLM; scope containment | `ACTION_NOT_PERMITTED`, `TARGET_NOT_PERMITTED` |
| 3b | **Silent scope expansion**: broaden the grant + refresh a token with no fresh human ceremony | undetected | **undetected** (honors live scope; no immutable human grant) | `DelegationToken` scope ⊆ immutable signed `HumanAuthReceipt`; widening needs a new signed human grant | `SCOPE_EXCEEDS_PARENT` |
| 3c | Relabel a HIGH action `LOW` (loose `freshnessBound.riskClass`) to skip attestation | n/a | n/a | riskClass per action is bound into the **signed policy** (`policy_hash`); the auditor takes the required risk from the policy by action, not the boundary's asserted label, and demands HIGH attestation regardless | `ATTESTATION_MISSING` (the boundary's `policyHash` continues to match because riskClass is now inside the signed snapshot; the relabel is caught at the attestation gate) |
| 4 | Compromised/buggy mediator asserts `PRE_EFFECT` on a revoked request | — | — | Auditor recomputes the decision from the ledgers and compares to the asserted status | `CHAIN_INTEGRITY_VIOLATION` |
| 5 | Tamper with a receipt's fields after issuance | — | — | Ed25519 over JCS(body); SHA-256 hash bindings | `INVALID_SIGNATURE`, `PARENT_HASH_MISMATCH` |
| 6 | Forge an `ExecutionResultReceipt` over a `BLOCKED`/absent boundary | — | — | Result→boundary binding + status check | `RESULT_FOR_BLOCKED_BOUNDARY`, `RESULT_WITHOUT_VALID_BOUNDARY` |
| 7 | Replay a previously authorized request | client's problem | client's problem | Atomic `NonceLog` / single-use `UsageLedger` | `NONCE_ALREADY_SEEN`, `USAGE_LIMIT_EXCEEDED` |
| 8 | Misuse the resource credential via the LLM | LLM/client holds the token | LLM/client holds the token | Credential starvation: only the adapter holds creds; only the mediator holds the signing key | (architectural) |
| 9 | Discredit a past-valid action because authority was later pulled | n/a | n/a | Point-in-time audit: `authorizedAtExecution` stays True; only `authorityLiveNow` flips | (two-verdict result) |

**Note on backdating (rows 2b–2d) — now closed by an attested clock.** The
head-signature check (2b) stops a *forged* `capturedAt`; the stale-head
cross-check (2c) stops quoting an *authentic but pre-revocation* head as long as
one chain timestamp is honest. Row 2d — backdating *every* self-asserted
timestamp — was previously the open residual, and is now closed, **but only
because two independent properties hold together**:

1. **The time authority stamps its own clock as a separate principal.** The
   quorum owns its `clock` and `radius`; `prove(nonce=…)` stamps
   `midpoint = self.clock()` and ignores any caller-supplied time. The mediator
   holds no time-authority key and cannot influence `midpoint`, so it cannot pull
   `t_ub = midpoint + radius` earlier than the honest clock. (If `prove` accepted
   a caller midpoint — the original flaw — a backdating mediator would simply ask
   for `midpoint = T0` and the whole mechanism would be theatre.)
2. **The proof binds an unpredictable post-effect token.** The nonce is
   `H(ExecutionResultReceipt)`, which includes `effectRef` — an unguessable,
   server-assigned id minted only at execution. So a proof cannot be **pre-fetched**
   at T0 against a predicted result and then attached to the real effect: the real
   `effectRef` (unknown at T0) won't match the pre-fetched nonce
   (`ATTESTATION_NONCE_UNBOUND`).

With both, `t_ub` is a provable upper bound on completion and revocation re-keyed
to it means "no revocation effective by `t_ub`". Drop *either* property and 2d
re-opens. The optional lower-bound proof (`t_lb = midpoint − radius`) plus
`maxAttestationWindowMs` bound the sandwich and catch a stale lower bound; it is
secondary hardening.

**riskClass binding (row 3c).** The attestation requirement is only as strong as
the labelling that triggers it. The required risk per action is therefore part of
the **signed policy** (folded into `policy_hash`), and the auditor derives the
required risk *from the policy by action* — never from the boundary's asserted
`freshnessBound.riskClass`. A mediator that relabels a HIGH delete `LOW` to skip
attestation still faces the HIGH requirement and is caught (`ATTESTATION_MISSING`).

**New residual risks introduced by the attested clock.**

- **Quorum compromise.** Security now rests on ≥ k of the n time authorities
  being honest. A single compromised server is tolerated (k-of-n), but an
  attacker controlling ≥ k authorities can mint a backdated `midpoint` and
  re-open the seam. Diversity and independence of the authorities is load-bearing.
- **Availability coupling.** A HIGH effect that cannot obtain a proof fails
  closed (`ATTESTATION_MISSING`). Effect throughput is now coupled to quorum
  availability — a deliberate availability/security trade-off.
- **Radius resolution floor.** Two events closer together than the attestation
  `radius` cannot be ordered by the proof. A revocation and an effect within the
  same radius window are indistinguishable; the conservative `t_ub` errs toward
  denial, but the radius is a hard resolution floor.

**Clock-source taxonomy.** `ntp` / NTS is **clock-hygiene only** — it keeps a
host's wall clock roughly correct but produces **no portable proof** an auditor
can later verify, so it does not close 2d. The portable-proof options are
**Roughtime** (nonce-bound signed time, modelled here) and an **RFC 3161 TSA**
(timestamp over a document hash); either yields an artifact a third party can
re-verify offline.

**Truncated-snapshot assumption.** The stale-head cross-check (2c) and the
`t_ub` revocation re-key both assume the auditor sees a **sequence-complete,
authority-signed revocation range** up to the head's `sequenceNumber`. A
truncated snapshot — one missing revocation entries below the head's sequence —
could hide a relevant revocation. The head's signed `sequenceNumber` is what lets
an auditor detect a gap (entries must be contiguous up to it); a production
deployment must verify range completeness against that signed sequence, not just
trust the entries it was handed.

## What is explicitly **out of scope** for the chain

Per `pfc-mediated-agent`, PFC governs whether the agent may **act** — not whether
its output is true and not whether a message is deliverable. The following live
in the channel/output layers, never in the mediator:

- output correctness / hallucination,
- transport authenticity and rate/delivery limits,
- recipient verification and messaging-window rules.

## Residual risk and simplifications

This is a demonstration, not a production library. Known simplifications:

- **JCS** is implemented as the sorted-keys / no-whitespace subset of RFC 8785;
  it is canonical for the string/integer/object artifacts used here but does not
  implement full number canonicalization.
- Ledgers are in-memory and single-process; "atomic" operations are atomic only
  under that assumption. A real deployment needs durable, linearizable ledgers.
- Key distribution and the WebAuthn-style governance ceremony are stubbed. The
  ledger head is authority-signed (`revocation-service`) and HIGH effects are now
  anchored to an attested-clock quorum (`MockRoughtimeQuorum`). The Roughtime
  **network** is stubbed (no UDP wire); the signing and k-of-n verification logic
  is real. A real deployment swaps the mock for live Roughtime / an RFC 3161 TSA.
- A subset of the v0.13 invariants is implemented — the ones the gap exercises.
  The full vocabulary and rule set live in the `pfc-delegation-chain` skill.
- The biggest residual risk in any real instantiation is **liveness of the
  revocation ledger**: the `FreshnessBound` only bounds *staleness* of an
  authority-signed view, it cannot manufacture a view the authority never signed.
  An unreachable ledger must fail closed (deny) — a deliberate
  availability/security trade-off.
