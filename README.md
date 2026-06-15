# pfc-mcp-authority-gap

A minimal, fully runnable demonstration of the **MCP authority gap**: under the
OAuth 2.1 bearer-token authorization model of the 2026-07-28 stateless MCP
profile, an agent can successfully execute a tool call whose underlying
authority was **revoked after the token was issued** — with no detection — and a
demonstration of how a PFC mediator closes that gap by failing closed and
emitting an independently verifiable receipt chain.

```
pfc-mcp-authority-gap/
├── pfc/             # minimal PFC delegation-chain library (shared)
├── vulnerable/      # stock MCP client + server, stateless OAuth 2.1 bearer
├── diligent/        # vulnerable + RFC 7662 introspection + 15m TTL (closes the gap, see LIMITS.md)
├── governed/        # same flow behind a PFC mediator, + standalone auditor.py
├── tests/           # pytest: vulnerable passes-then-acts; diligent closes-but-lacks; governed denies-and-attests
├── README.md
└── THREAT_MODEL.md
```

The chain and receipt semantics follow PFC's internal specification artifacts
(`pfc-delegation-chain` and `pfc-mediated-agent`), but **this repository is fully
self-contained and runnable without them**: `pfc/` is a faithful standalone
subset of the v0.13 four-artifact chain, and an outside reader needs nothing
external to read, run, or audit any of it. Those artifacts are cited only to show
where the canonical semantics live, not as a dependency.

---

## The gap

OAuth 2.1 access tokens are **bearer** tokens: possession is sufficient, and a
resource server validates them **statelessly** — signature, audience, expiry,
and the `scope` claim — with no token-introspection round-trip on the request
path. The stateless MCP profile **permits** this local-validation pattern, and it
is the common deployment — not a mandate. `vulnerable/` implements that honest,
permitted baseline faithfully (it is not a strawman).

The consequence is a **time-of-authorization vs. time-of-use** gap:

1. `T0` — the authorization server issues the agent a token (`scope: crm:delete`,
   1-hour TTL).
2. `T0 + 5m` — the underlying authority is **revoked** at the AS (a security
   incident; the admin pulls the agent's grant). RFC 7662 introspection would
   now report `active: false`.
3. `T0 + 10m` — the agent calls `delete_contact`. The stateless server validates
   the token locally: signature ✔, audience ✔, not expired ✔, scope present ✔ →
   **the delete executes.** The server never consulted the revocation, because
   nothing on the request path requires it to. **Passes, then acts.**

Revocation is not *impossible* in OAuth — it is simply **not on the hot path**.
The token stays cryptographically valid until its own `exp`. For a long-lived
agent holding a bearer token, "revoked" means "revoked whenever the token
happens to expire," not "revoked now."

## The NSA framing

NSA's Zero Trust guidance is built on **"never trust, always verify"**, and its
application/workload-pillar Cybersecurity Information Sheet stresses that access
decisions must be **evaluated continuously and enforced automatically** — not
granted once and assumed to hold. A self-contained bearer token that a resource
server checks only against its own signature and expiry is the antithesis of
continuous authorization: it is a **standing privilege** frozen at issuance.
Under a "least privilege / assume breach" posture, the moment a grant is pulled
it must stop being honored — promptly, on the next request, not at the next
token-expiry boundary.

The MCP authority gap is therefore a concrete instance of the failure mode Zero
Trust is meant to eliminate: authority that **outlives** its authorization.

## A diligent baseline (and why it isn't enough)

`diligent/` is the strongest baseline that stays within plain OAuth: it performs
**RFC 7662 introspection on every effectful call** (authorizing against the
*live* scope) and issues **15-minute tokens**. This genuinely **closes the
revoke-after-issue gap** — `python -m diligent.demo` shows the revoked delete
denied. It is not a strawman; for many systems it is enough.

But diligence improves only the *liveness* of the check. Four properties the PFC
path provides are missing — three of them **structural absences** (OAuth has no
construct for them), and the fourth a matter of **no native anchor / no interop
standard, so unenforced in practice**. Each is proven by a test
(`tests/test_diligent.py`) and documented in `diligent/LIMITS.md`:

1. **No signed, action-bound attestation** *(structural)* — the decision is an
   unsigned audit line, not a receipt bound to the action + payload.
2. **No per-action-class freshness object** *(structural)* — introspection is
   binary, with no declared staleness bound a HIGH-risk action could tighten.
3. **No trustless re-derivation** *(structural)* — the only evidence is the
   server's own, unsigned log; verifying it means trusting the server.
4. **Silent scope expansion goes unenforced** *(no native anchor / no interop
   standard)* — authorizing off live scope, it honors a grant broadened and
   refreshed with no fresh human ceremony. Defending this isn't impossible to
   bolt on (a custom claim, a policy diff, a RAR convention), but OAuth offers
   no standard immutable human-grant object for resource servers to check
   against, so in practice nothing does. PFC makes that anchor native
   (`DelegationToken` ⊆ signed `HumanAuthReceipt`, `SCOPE_EXCEEDS_PARENT`).

## How PFC closes it

In `governed/`, the same agent never holds a credential or a signing key (it is
**not** a principal in the chain). It only emits an
untrusted `ActionRequest`. A **mediator** (the enforcement point) maps that
request onto the delegation chain and, on **every effectful request**:

- captures a **fresh** view of the live authority ledger (the `RevocationLog`),
- enforces a **per-action-class `FreshnessBound`** (a `HIGH`-risk `delete` must
  be decided against a ledger view no older than 30s), and
- runs full chain verification, **failing closed** on any violation.

When the authority has been revoked, the mediator fixes the `BoundaryReceipt`
status at `BLOCKED` **before any effect**, never calls the credentialed adapter,
and the contact survives. The signed `BLOCKED` receipt is the **attestation of
the denial**. An allowed request instead produces the full
`HumanAuthReceipt → DelegationToken → BoundaryReceipt → ExecutionResultReceipt`
chain.

`governed/auditor.py` then verifies that chain **without trusting the mediator**
— see the scope of that claim below. It consumes only public keys, a revocation
snapshot, and the signed artifacts; re-checks every signature and hash binding;
verifies the **authority-signed ledger head**; and **recomputes the
authorization decision from the ledgers**, comparing it to the status the
mediator asserted. A mediator that stamps `PRE_EFFECT` on a revoked request —
even with a valid signature — is caught as a `CHAIN_INTEGRITY_VIOLATION`; a
mediator that forges a fresh `capturedAt` over a stale ledger head is caught as a
`FRESHNESS_VIOLATION` (the head's signature no longer matches); and a mediator
that backdates `verifiedAt` while quoting an *authentic* pre-revocation head is
caught as a `STALE_HEAD_VS_KNOWN_REVOCATION` — the auditor ties the quoted head
to the action's own completion time and requires it to postdate every revocation
effective by then.

The last seam — a mediator that backdates **every** self-asserted timestamp —
is closed by an **attested clock**, and only because two properties hold
together: (1) the time-authority quorum is a **separate principal** that stamps
its *own* clock and radius (`prove()` ignores any caller-supplied time, so the
mediator can't move `t_ub` by lying about its clock), and (2) the upper-bound
`TimeProof`'s nonce binds `H(ExecutionResultReceipt)` including an **unpredictable
post-effect `effectRef`**, so a proof can't be pre-fetched at T0 against a guessed
result. `t_ub = midpoint + radius` is then a provable upper bound on completion;
the auditor re-keys revocation to it, so `authorizedAtExecution` becomes **"no
revocation effective by `t_ub`"** — a real T0+600 effect against a T0+300
revocation is denied no matter how the receipts are dated. Drop either property
and the seam re-opens. The required **risk class is itself bound into the signed
policy** (`policy_hash`), so a mediator can't relabel a HIGH delete `LOW` to skip
attestation. Faults: `ATTESTATION_MISSING` / `_NONCE_UNBOUND` / `_QUORUM_NOT_MET`
/ `_INVALID_SIGNATURE` / `_WINDOW_EXCEEDED` / `_INTERVAL_INCONSISTENT` (see
`THREAT_MODEL.md` for residuals: quorum compromise, availability coupling, radius
resolution floor).

The audit reports **two distinct verdicts** rather than one boolean, because
revocation is **point-in-time** (a revocation takes effect from its `revokedAt`):

- `authorizedAtExecution` — was the action authorized **as of its own
  `verifiedAt`/`completedAt`**? A delete that ran *before* the grant was pulled
  stays `True` forever; it never reads as "never authorized" just because
  authority was later revoked.
- `authorityLiveNow` — is that authority **still live as of `evaluatedAt`**?
  Evaluated as of an explicit `evaluatedAt` carried in the audit bundle (the CLI
  defaults it to the latest timestamp in the artifacts), not wall-clock time, so
  the verdict is deterministic and you can ask "was authority live as of date X?"

### Scope of the "trustless" claim

The audit is **trustless given an authority-signed ledger head and a k-of-n
honest time-authority quorum**. The revocation service signs every
`{sequenceNumber, headHash, capturedAt}` (so the mediator cannot fabricate a
freshness view), and the time authorities sign every `{nonce, midpoint, radius}`
(so the mediator cannot fabricate *when*). What remains trusted: that the
revocation-service key is honest, and that **≥ k of the n** time authorities are
honest. A minority compromise is tolerated; control of ≥ k authorities, or an
unsigned ledger range, is the residual (see `THREAT_MODEL.md`).

| | `vulnerable/` | `diligent/` | `governed/` (PFC) |
|---|---|---|---|
| Authority re-checked per request | No (sig/aud/exp/scope only) | Yes (live introspection) | Yes (live ledger) |
| Revoked-after-issuance call | **Executes**, undetected | **Blocked** | **Blocked**, no effect |
| Per-action-class freshness bound | No | No (binary, no staleness bound) | Yes (`FreshnessBound`, signed head) |
| Signed, action-bound attestation | No | No (unsigned log line) | Yes (`BoundaryReceipt`/`ExecutionResultReceipt`) |
| Trustless re-derivation by a third party | No | No (trust the server's log) | Yes (given a signed ledger head) |
| Silent scope expansion past human grant | Undetected | Undetected | Blocked (`SCOPE_EXCEEDS_PARENT`) |
| Point-in-time vs. live verdict | n/a | n/a | `authorizedAtExecution` + `authorityLiveNow` |
| Backdating every timestamp | n/a | n/a | Blocked via attested `t_ub` (k-of-n `TimeProof`) |

---

## Repro steps

Requires Python 3.10+.

On systems without a bare `python`/`pip` alias (most Linux and macOS), use
`python3` and `pip3` for every command below.

```bash
cd pfc-mcp-authority-gap
pip install -r requirements.txt          # or: pip3 install -r requirements.txt  (cryptography, pytest)

# 1. The gap: revoked authority still acts, no detection.
python -m vulnerable.demo

# 2. The diligent baseline: introspection + 15m TTL closes the gap (but see LIMITS.md).
python -m diligent.demo

# 3. The full closure: same flow, fail-closed + full receipt chain + point-in-time audit.
python -m governed.demo                  # writes audit bundles to governed/_bundles/

# 4. Independently audit the BLOCKED chain without trusting the mediator.
python -m governed.auditor governed/_bundles/episode2_blocked.json

# 5. The proof: vulnerable passes-then-acts; diligent closes-but-lacks; governed denies-and-attests.
python -m pytest -q
```

Expected: the vulnerable delete returns `deleted: True` on a revoked grant; the
diligent delete is denied (`gap_closed=True`); the governed delete returns
`BLOCKED` with the contact intact; the auditor reports `chainIntact=True,
authorizedAtExecution=False, authorityLiveNow=False, ['ROOT_RECEIPT_REVOKED']`;
all tests pass.

See `THREAT_MODEL.md` for the trust boundaries, attacker model, and exactly which
invariant stops each move.

## Contributing / found a flaw?

Adversarial review is the point. If you find a hole in the threat model, a way
past the auditor, or a bug in the chain logic, please open an issue — concrete
attacks on `governed/` and its `auditor.py` are especially welcome.

## Sources

- [MCP 2026-07-28 release candidate — maintainer announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP authorization specification (current stable, 2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [NSA — *MCP: Security Design Considerations for AI-Driven Automation* (CSI PDF)](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)
- [NSA — *Advancing Zero Trust Maturity Throughout the Application and Workload Pillar*](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3784301/nsa-releases-guidance-on-zero-trust-maturity-throughout-the-application-and-wor/)
- Chain/receipt semantics follow PFC's internal specification artifacts
  `pfc-delegation-chain` (v0.13) and `pfc-mediated-agent` (v0.1); this repo
  reproduces a faithful, self-contained subset and requires neither to run.
