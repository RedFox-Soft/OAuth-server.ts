---
type: concept
title: "A browser application's refresh-token chain is bounded by its first lifetime"
tags: [contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-23
---

# A browser application's refresh-token chain is bounded by its first lifetime

A public web client — a single-page application, `applicationType: 'web'` with
`token_endpoint_auth_method: 'none'` — whose refresh tokens are **not** sender-constrained has its
tokens rotated on every use (`rotateRefreshToken`, `lib/addon/tokens.ts:74-95`). Rotation alone does
not bound anything: if every rotated token got a fresh lifetime, a stolen token could be kept alive
indefinitely just by using it. So for exactly these clients the rotated token inherits the *remaining*
lifetime of its chain, and the chain ends when its first token would have.

A confidential client, or a public one whose refresh token is DPoP- or mTLS-bound, gets a full lifetime
on rotation: a stolen token is useless without the key, so there is nothing to bound.

## Decided from the token's own record

The rule lives in `ttl.RefreshToken` (`lib/configs/liveTime.ts:64`) and reads only the token being
minted and its client:

- `payload.iiat` — the chain's first issuance, set once and copied by every rotation
  (`lib/models/refresh_token.ts:17,36-37`);
- `payload.rotations` — incremented by every rotation (`lib/models/refresh_token.ts:20`).

A rotated token (`rotations >= 1`) of such a client lives `iiat + lifetime − now`, floored at one
second. The floor is not cosmetic: `BaseToken#expiration` treats a falsy `expiresIn` as "not computed
yet", so a zero would be recomputed rather than honoured.

It is decided from the record, not from the request, because a lifetime is computed lazily — the
first time `expiration` is read — and that is not guaranteed to be inside a request. Every lifetime
function therefore takes `(token, client)` and nothing else.

## How it went dead, and why nobody noticed

The rule used to read the rotated predecessor off the request context, which reached the lifetime
function through an `AsyncLocalStorage` filled by the Koa middleware stack. `54ba556` ("drop ctx
context") removed that stack and with it the only `als.run(...)`; the store stayed, empty. From then
on the rule's condition read `undefined` and was never taken, and no test covered it.

It stayed invisible because **the grant covered for it**. Every rotation keeps `grantId`; a `Grant`
is a `BaseToken` whose expiry is fixed at first save, because `save()` re-saves with
`remainingTTL` (`lib/models/base_token.ts:99`); refresh refuses an expired grant
(`lib/actions/grants/refresh_token.ts:84`); and the default grant lifetime equals the default
refresh-token lifetime, fourteen days. So with defaults a browser chain died at the grant's end
anyway. The hole opens whenever a grant outlives the refresh-token lifetime — then the only
remaining bound is the one-year rotation cap (`lib/addon/tokens.ts:79`).

Restored in `060-typed-oidc-context`, with the ambient store deleted. The test
(`test/refresh/browser_chain.spec.ts`) states its condition — the grant outlives the chain — because
without it the grant would end the chain at the same moment and prove nothing about this rule.

## Upgrade consequence

A browser chain extended while the rule was dead may already be older than its first lifetime. Its
next rotation after the upgrade is bounded by `iiat`, so it ends and the end user signs in again.
With default lifetimes such a chain cannot exist (its grant would have expired first), so this only
reaches deployments that changed a lifetime.

## Related

- [[token-payload-access-contract]] — the same class of defect: a read that yields `undefined`
  silently instead of failing.
- [[addon-registry]] — `rotateRefreshToken` is an overridable seam; the bound applies to whatever it
  decides to rotate.
