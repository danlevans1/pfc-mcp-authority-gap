# Execution-Time Authority Integrity in MCP

*A note for the MCP working group and spec maintainers.*

## The gap, in protocol terms

MCP's authorization model is OAuth 2.1 bearer tokens carried at the transport
layer. Authorization is optional, and the 2026-07-28 stateless profile has a
resource server validate an access token **locally** on each call — signature,
audience, expiry, and the `scope` claim — with no token-introspection round trip
on the request path. This is a reasonable performance posture and we treat it as
the honest baseline, not a strawman.

It has one consequence worth naming precisely. Validation is a function of the
token, and the token is frozen at issuance. So the resource server can answer
"is this token well-formed and unexpired?" but it cannot answer "is the authority
behind this token still valid *right now*?" — and nothing downstream can answer
"was that authority valid **at the instant the tool actually executed**?"

We call that last property **Execution-Time Authority Integrity (ETAI)**:

> An independent verifier can determine whether the authority for an action was
> valid at the instant the action executed.

ETAI is the property the bearer model does not provide and, as far as we can
tell, no MCP authorization profile currently provides. The rest of this note is
about what it takes to get it, and the narrow question of whether any of it
belongs in the spec.

A concrete instance. At `T0` the AS issues an agent a token (`scope: crm:delete`,
1-hour TTL). At `T0+5m` the grant is revoked at the AS — a security incident, an
admin pulls the agent's authority; RFC 7662 introspection would now return
`active: false`. At `T0+10m` the agent calls `delete_contact`. Stateless
validation passes (signature ✔, audience ✔, not expired ✔, scope present ✔) and
the delete executes. Revocation was never on the request path. Revocation is not
*impossible* in OAuth; it is simply not consulted before the token's own `exp`.
For a long-lived agent, "revoked" means "revoked whenever the token happens to
expire," which is the absence of ETAI.

## Three paths

We built a minimal, runnable comparison (three implementations of the same CRM
delete flow) to separate what is a protocol limitation from what is an
implementation choice.

**`vulnerable/` — executes.** A stock stateless OAuth 2.1 resource server. The
revoked-after-issue delete runs, undetected. This is the 2026-07-28 profile
implemented faithfully.

**`diligent/` — introspects, closes revocation, but cannot attest.** The
strongest baseline that stays within plain OAuth: RFC 7662 introspection on every
effectful call (authorizing against *live* scope) plus 15-minute tokens. This
**closes the revoke-after-issue gap** — the revoked delete is denied. For many
deployments that is enough. But diligence improves only the *liveness* of the
check; it does not produce ETAI. The decision is an unsigned log line, not a
signed artifact bound to the action and payload; there is no per-action staleness
bound; and verifying that the server decided correctly means **trusting the
server's own log**. There is no object a third party can independently re-derive
the verdict from.

**`governed/` — denies and proves.** The same flow behind a PFC mediator. The
agent (the LLM) holds no credential and no signing key; it emits an untrusted
request. The mediator re-resolves the live authority ledger on every effectful
request, applies a per-action freshness bound, and **fixes the boundary status
fail-closed before any effect**. A revoked authority yields a signed `BLOCKED`
boundary and the resource adapter is never called. An allowed action yields the
full `HumanAuthReceipt → DelegationToken → BoundaryReceipt → ExecutionResultReceipt`
chain.

The distinction we want to put in front of the working group is this: **these
receipts are not after-the-fact audit logs.** They are evidence of the decision
that actually gated execution — because revocation is re-evaluated at decision
time and the boundary status is fixed, fail-closed, *before* any effect occurs.
The receipt is not a description of what happened written afterward; it is the
artifact the enforcement point produced in order to let (or refuse) the effect.
That is what makes ETAI verifiable rather than merely logged.

## The centerpiece: a verifier that doesn't trust the enforcement point

The receipts would be worth little if confirming them required trusting the
party that issued them. So the load-bearing component is a standalone auditor
that **re-derives the authorization verdict from public material** — public keys,
a signed revocation snapshot, the signed artifacts — and never asks the mediator
whether its own decision was correct.

The auditor re-checks every signature and hash binding, verifies the
authority-signed ledger head, and then **recomputes the authorization outcome
from the ledgers and compares it to the status the mediator asserted.** A
mediator that stamps an allowed status on an action the ledgers say was revoked
is caught (`CHAIN_INTEGRITY_VIOLATION`) even though its signature is perfectly
valid. The verdict is reported as two distinct values rather than one boolean,
because revocation is point-in-time: `authorizedAtExecution` (was authority valid
at the action's own instant — which stays true for a past action even after
authority is later pulled) and `authorityLiveNow` (is it still valid as of an
explicit evaluation time). That separation is itself part of ETAI: a correctly
authorized past action must not read as unauthorized merely because the grant was
revoked afterward.

One timing subtlety the working group will recognize: a malicious enforcement
point can backdate every timestamp it controls. Closing that requires anchoring
the action to an **external clock the enforcement point cannot influence** — a
named trust assumption, not free. We summarize the mechanism in Appendix A; the
point for this discussion is only that ETAI's time dimension is achievable but
costs an explicit dependency.

(Silent scope expansion — an agent's authority being broadened past what a human
actually granted — is a *distinct* failure mode the same delegation chain
addresses, by binding every token to an immutable signed human grant; it is out
of scope for this note.)

## Composition and trust base

PFC here is a **verifiable-authority layer that composes with MCP's OAuth**, not
a competing protocol. OAuth still authenticates and carries the token; the
mediator adds an enforcement point that re-checks live authority and emits the
ETAI artifact. Nothing about the transport changes.

We state the trust base plainly, because ETAI does not come for free:

- **Revocation-service signing.** Freshness rests on an authority-signed ledger
  head; a verifier trusts that signing key.
- **k-of-n time quorum.** The execution-time bound rests on ≥ k of n independent
  time authorities being honest. A minority compromise is tolerated; control of
  ≥ k re-opens the timing seam.
- **Availability coupling.** An effect that cannot obtain its attestation fails
  closed, so effect throughput is coupled to quorum availability — a deliberate
  trade-off.
- **Radius floor.** Two events closer together than the attestation radius cannot
  be ordered; the bound errs toward denial, but the radius is a hard resolution
  floor.

These are real and worth naming. They are also bounded and local, which is the
case for ETAI being an achievable application-layer property rather than an
open-ended research problem.

## Scope boundary

ETAI can live entirely at the application layer; our implementation does, and it
composes with the existing OAuth profile without spec changes. We are **not**
asking MCP to implement enforcement, to mandate revocation semantics, or to ship
a mediator. The enforcement point, the ledgers, and the time quorum are
deployment concerns and should stay there.

The narrower question is **interoperability of evidence**. If two
implementations each produce a verifiable-authority artifact but in different
shapes, a relying party cannot audit across them, and the property stops being
portable. So the open question for the working group is whether the **receipt /
attestation shape** — the structure of the artifact that lets an independent
party re-derive an execution-time authority verdict — should be defined by the
spec so implementations interoperate, or left wholly to the ecosystem. That is a
decision about whether the *artifact* is in scope to standardize, not about
whether the spec should enforce anything.

## The ask

Three scoped questions:

1. Independent of (2)–(3): should the authorization profile **document** the
   time-of-authorization vs. time-of-use gap of the stateless bearer path, so
   implementers choose introspection/TTL or an attestation layer deliberately
   rather than by omission?
2. Is **Execution-Time Authority Integrity** — an independently verifiable
   answer to "was the authority valid at the instant the action executed?" — a
   property the working group considers in scope for MCP authorization to
   address, or explicitly out of scope and left to deployments?
3. If in scope: should the spec define the **receipt/attestation shape** (the
   verifiable-authority artifact) for interoperability, while leaving enforcement,
   revocation transport, and freshness policy to implementations?

Reference implementation (runnable, three paths, standalone auditor, full test
suite): **[repository link — placeholder]**.

## Appendix A: Hardening against timestamp manipulation

The auditor's verdict re-keys revocation to the action's *attested* completion
time rather than any self-asserted timestamp. The mechanism:

- A HIGH-class effect must carry a **k-of-n quorum-signed upper-bound time
  proof**. The proof's nonce is `H(ExecutionResultReceipt)` and that hash
  includes an **unpredictable, server-assigned `effectRef`** minted only at
  execution. Two properties must hold together: (i) the time quorum is a separate
  principal that stamps its *own* clock and radius and ignores any caller-supplied
  time, so the enforcement point cannot move the bound by lying about its clock;
  and (ii) the unpredictable `effectRef` means a proof cannot be pre-fetched at
  `T0` against a guessed result. Drop either and the seam re-opens.
- From the proof, `t_ub = midpoint + radius` is a provable upper bound on the
  true completion time. "Authorized at execution" then means **"no revocation
  effective by `t_ub`"** — a real `T0+600` effect against a `T0+300` revocation
  is denied regardless of how the receipts are dated.
- An optional pre-effect **lower-bound proof** (`t_lb = midpoint − radius`) plus a
  `maxAttestationWindowMs` cap bound the sandwich `[t_lb, t_ub]` and catch a stale
  lower bound. This is secondary hardening.
- The required risk class is bound into the **signed policy** (it is folded into
  the policy hash), and the auditor derives the required risk from the policy by
  action — never from the boundary's asserted label — so an enforcement point
  cannot relabel a HIGH action LOW to skip attestation.
- Clock-source note: NTP/NTS is clock *hygiene* and produces no portable proof;
  the portable options are Roughtime (nonce-bound signed time) or an RFC 3161
  timestamp authority. The cross-checks also assume a sequence-complete,
  authority-signed revocation range up to the signed ledger-head sequence number.

Fault codes surfaced by the auditor for this layer: `ATTESTATION_MISSING`,
`ATTESTATION_NONCE_UNBOUND`, `ATTESTATION_QUORUM_NOT_MET`,
`ATTESTATION_INVALID_SIGNATURE`, `ATTESTATION_WINDOW_EXCEEDED`,
`ATTESTATION_INTERVAL_INCONSISTENT`.

## Sources

- MCP **2026-07-28 release candidate** (locked May 21, 2026; final targeted
  July 28, 2026; currently in validation) — maintainer announcement (primary):
  <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>.
  Companion authorization spec text:
  <https://modelcontextprotocol.io/specification/draft/basic/authorization>.
- MCP authorization specification — current stable authorization framework
  (OAuth 2.1 binding), version 2025-11-25:
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>.
- NSA, *Model Context Protocol (MCP): Security Design Considerations for
  AI-Driven Automation* (May 2026) — CSI PDF (primary):
  <https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf>;
  press release (secondary):
  <https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/>.
- NSA, *Advancing Zero Trust Maturity Throughout the Application and Workload
  Pillar* (2024) — CSI PDF:
  <https://media.defense.gov/2024/May/22/2003470825/-1/-1/0/CSI-APPLICATION-AND-WORKLOAD-PILLAR.PDF>.
