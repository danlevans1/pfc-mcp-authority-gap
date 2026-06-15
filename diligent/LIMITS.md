# What the diligent baseline still lacks

The `diligent/` server closes the **revoke-after-issue** gap: by introspecting
(RFC 7662) on every effectful call and authorizing against the **live** scope,
plus issuing 15-minute tokens, a pulled grant stops being honored on the next
request instead of at token expiry. `python -m diligent.demo` shows the revoked
delete being denied.

That is real progress, and for many deployments it is enough. But it is still
plain OAuth + introspection, and four properties the PFC `governed/` path
provides are missing. Three of them (#1–#3) are **structural absences** — the
protocol has no construct for them at all. The fourth (#4) is different in kind:
it is **not** structurally impossible to bolt on, but OAuth/introspection has
**no native anchor for it and no interop standard**, so in practice it is
**unenforced**. Each is proven by a test in `tests/test_diligent.py`.

## 1. No signed, action-bound attestation

The diligent server returns a plain result dict and writes a line to its own
audit log. Nothing is **signed**, and nothing **binds the decision to the exact
action and payload** that was authorized. There is no artifact a third party can
hold up later and say "this specific delete of `c-1001` was authorized at this
instant, by this enforcement point." Introspection answers "is this token
active?" — not "was *this action* authorized, provably?"

PFC emits a `BoundaryReceipt` (and, on success, an `ExecutionResultReceipt`)
signed over the action, target and payload hash.

*Test:* `test_no_signed_action_bound_attestation`.

## 2. No per-action-class freshness object

Introspection is binary (`active` / `inactive`) and carries **no declared
staleness bound**. A resource server is free to cache introspection responses,
and nothing in the protocol says how old a cached "active" may be before a
HIGH-risk delete must refuse it. There is no `FreshnessBound {maxAgeMs,
riskClass}` object, and no way to make a delete demand a fresher authority view
than a read.

PFC carries a per-action-class `FreshnessBound` and a signed `LedgerHeadRef`
(`capturedAt`), and refuses a stale view with `FRESHNESS_VIOLATION`.

*Test:* `test_no_per_action_class_freshness_object`.

## 3. No trustless re-derivation

The only evidence the diligent decision ever happened is the server's **own,
unsigned** audit log. Verifying it means **trusting the server**. There is no
portable, public-key-verifiable bundle a separate party can replay to
re-derive the verdict, and no way to catch a server that logged "allowed" when
the live authority actually said "deny."

PFC's `auditor.py` re-derives the verdict from public keys + a ledger snapshot +
the signed artifacts, and catches an enforcement point that asserts a status the
ledgers do not support.

*Test:* `test_no_trustless_re_derivation`.

## 4. Silent scope expansion: no native anchor, unenforced in practice

This one is a different kind of gap from #1–#3. Because the diligent server
authorizes against the **live** introspection scope, it honors whatever scope
the AS currently reports. If the subject's grant is broadened — and a refreshed
token minted — **with no fresh human-in-the-loop authorization**, the agent's
authority silently grows, and the server compares it against nothing.

The distinction worth being precise about: this is **not structurally
impossible** to defend in OAuth. You could pin an original-grant hash in a custom
claim, run a policy service that diffs live scope against a stored human
approval, or layer a Rich Authorization Requests (RAR) convention on top.
Nothing in the protocol forbids it. What's missing is a **native anchor** — there
is no standard, immutable, human-signed grant object that downstream resource
servers are required to (or interoperably can) check against — and **no interop
standard** for one. So in real deployments it is simply **unenforced**: the
introspection response is the ceiling, and the original human intent is not
represented anywhere the resource server consults.

PFC makes the anchor native and load-bearing: every `DelegationToken` is bound
by hash to an immutable, signed `HumanAuthReceipt` whose
`permittedActions`/`permittedTargets` are the ceiling. A token may only ever
*narrow* that scope (`SCOPE_EXCEEDS_PARENT` otherwise), and the binding is part
of what the auditor verifies — so widening requires a new signed human grant and
cannot happen silently.

*Test:* `test_silent_scope_expansion_is_undetected`.

---

In short: diligence makes the *liveness* check better. It still does not make the
decision **attested**, **freshness-typed**, or **independently verifiable** —
three constructs OAuth simply has no place for (#1–#3). And while anchoring to an
immutable human grant (#4) is not impossible in principle, OAuth offers no native
anchor and no interop standard for it, so it goes **unenforced in practice**.
Those four properties are what the delegation chain makes native and checkable.
