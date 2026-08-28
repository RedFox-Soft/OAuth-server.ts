---
type: concept
title: "Per-origin rate limiting"
tags: [architecture, config, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-28
updated: 2026-08-28
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:event-bus
      source: oauth-server-codebase
      evidence: "eventBus.emit('rate_limited', { method, path, class: rateClass, origin });"
      confidence: high
      status: current
---

# Per-origin rate limiting

Requests are counted per calling origin and refused with `429` once an origin spends its allowance
inside a window. Three things about it cannot be re-derived from reading the code, and they are the
reason this page exists.

## The mount order is a correctness decision, not a performance one

`lib/index.ts` mounts the limiter **before** `featureGate`:

```
nocache → securityHeaders → rateLimit → featureGate → corsPreflight
```

The instinct is the opposite — gate first, so a capability-disabled endpoint costs no allowance. That
ordering breaks [[feature-flag-gating]]'s central property. Measured both ways:

| Order | Disabled capability | Unserved path |
|---|---|---|
| gate, then limit | always `404` — never counted | `404`, then `429` under load |
| **limit, then gate** | `404`, then `429` under load | `404`, then `429` under load |

With the gate first, the two become distinguishable by volume alone: flood both, and only the one the
server *does* route starts answering `429`. That is exactly the fingerprint `featureGate` exists to
eliminate, arrived at by an ordering that looks like a micro-optimisation.

`test/rate_limit/exemptions.spec.ts` pins it. Reversing the two lines in `lib/index.ts` fails two of
its cases — verified by doing it, not by reasoning about it.

## The refusal is rendered at the root, because the throw precedes routing

`lib/plugins/rateLimit.ts` throws from an `onRequest` hook on the **root** instance. Elysia has not
dispatched into any mounted sub-instance at that point, so `adminApp.onError` never runs — a marker
on the error that makes the root handler stand aside hands the refusal to a handler that does not
execute, and the caller receives Elysia's bare fallback: the error's `message` as plain text, no
status shape, no headers.

That was measured. The console got `temporarily_unavailable` as a text body with no `Retry-After`
before `lib/shared/authorization_error_handler.ts` grew a `RateLimited` block ahead of its admin
stand-aside. The marker is still set for console paths, but it is read *there* to choose the body —
not to delegate.

The consequence for `/mcp`: it has an `onError` of its own that handles validation failures only, so
it deliberately receives the OAuth JSON body rather than a JSON-RPC error. Pinned by test so the
choice stays visible.

### The redirect trap

`OIDCProviderError` defaults `allow_redirect = true`, and the handler turns any redirectable error
raised on `/auth` into a redirect back to the client. `RateLimited` sets it to `false`. Without that,
a refusal at the authorization endpoint would be answered by resolving and validating `redirect_uri`
first — precisely the work the refusal exists to avoid — and would hand an attacker a redirect on an
endpoint they have already been told to stop calling. Nothing else would notice: a `302` to the
registered URI looks correct.

### The mis-filing trap

A `429` is neither `500` nor a gate refusal, so without an explicit exclusion it falls through the
handler's `else` and is announced on `server_error` — deliberate behaviour reported as a fault, on
the one channel an operator cannot afford to learn to ignore. The exclusion sits beside
`FeatureDisabled`'s, for the same reason. The error *store* needs none: it captures at `status >= 500`.

## Counters are bounded, in-process, and never persisted

One `QuickLRU` per route class, keyed by origin, sized by `rateLimit.maxTrackedOrigins`.

The bound is the load-bearing part. The key is supplied by the caller, so an unbounded `Map` is
itself the memory-exhaustion vector the limiter was added to prevent — strictly worse than having no
limiter, because an attacker rotating source addresses would consume memory rather than merely CPU.
Eviction under that flood means an honest origin can get a fresh allowance: it fails open under an
attack this cannot stop anyway, and never fails closed against honest traffic.

Nothing is written to storage. A per-request datastore round-trip would put a write in front of the
whole server to save the cost of the requests it refuses. So this feature adds **no** storage area,
no index, and no participation in the deletion cascade — see [[deletion-and-revocation]].

The price, stated in the README rather than hidden: with N machines serving concurrently the
effective allowance is N times the configured value, and a restart clears every counter. **This is a
resource protection, not a security boundary.** The limits that must hold absolutely live in the
per-identity throttles — the verification attempt cap and the cooldown/daily-cap arithmetic in
`lib/helpers/rate_window.ts` — which this feature leaves untouched and does not duplicate. Issue #9
(login-door brute force) remains separately necessary for the same reason.

## Classification, and why `ordinary` is the default

`RateClass` is the third dimension declared over the route table in
`lib/consts/route_classification.ts`, alongside the gate's and CORS's, under the same two-way drift
guard. An unclassified route resolves to `ordinary` — the opposite of `gatedRoutes`, where omission
fails the guard. Making omission mean *unlimited* would turn forgetting the table into opting out of
protection, silently. The guard still pins `strict`, `public` and `exempt` as exact sets, so the
decision cannot be skipped; it just fails toward more protection rather than less.

Every `OPTIONS` is `public` on the method alone. A preflight never reaches the route table —
`corsPreflight` short-circuits it — and charging it to the class of the request it precedes would
halve a browser client's real allowance, refusing it for requests it never sent.

## Gotcha: the counters leak between tests

The store is module state, so nothing in the suite clears it by default, and once enough requests
accumulate on the unattributed bucket, unrelated specs start seeing `429`s in whichever file happens
to cross the allowance first — 1039 failures, on the first full run after mounting. The reset lives
in `test/preload.ts`'s global `afterEach`, not in `bootstrap()`: the specs that trip it are the ones
calling `bootstrap` in `beforeAll`, where a per-file reset comes too late. See
[[bun-beforeeach-describe-scope]] for the related scoping rule.

## Related

- [[feature-flag-gating]] — the indistinguishability property the mount order protects, and the
  `feature_disabled` emit this feature's `rate_limited` emit is modelled on.
- [[non-html-response-hardening]] — the `onRequest` sibling whose measurements decided the hook stage;
  its headers are on every refusal because the limiter is mounted after it.
- [[html-response-security-policy]] — renders the HTML refusal via the handler's `Accept` branch.
- [[deletion-and-revocation]] — why a storage-free feature touches none of it.
- [[admin-plane-error-shape]] — the shape the console refusal has to match, and the stand-aside this
  feature had to be sequenced ahead of.
