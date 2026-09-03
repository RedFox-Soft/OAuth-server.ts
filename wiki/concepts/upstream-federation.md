---
type: concept
title: 'Signing in through somebody else’s identity provider'
tags: [architecture, contract, gotcha, oidc]
sources: [oauth-server-codebase]
created: 2026-08-05
updated: 2026-08-24
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:interaction-page-families
      source: oauth-server-codebase
      evidence: "loginServer(uid, { passwordLogin, providers })"
      confidence: high
      status: current
---

# Signing in through somebody else’s identity provider

A user bucket may carry generic OIDC providers, and this server becomes a **relying party** on them: the
login page offers each enabled provider, the user authenticates upstream, and an identity assertion is
turned into a local session. The relying-party discipline was already in the repository pointed inward —
`lib/admin/auth/login.ts` runs the same flow against this server's own issuer — so federation is that
discipline pointed outward.

## The three hops exist because the cookie cannot make the trip

This is the shape's whole reason, and it is not a preference.

The interaction cookie is `path: /ui/${uid}` and `sameSite: 'strict'`. An upstream provider matches
`redirect_uri` by **exact string**, so the callback URL must be identical for every interaction — it cannot
contain the `uid`. And the return leg is a cross-site top-level navigation, which carries no strict cookie
even if the path matched. So the callback provably cannot read the interaction cookie:

| Hop | Route | Cookie | Carries |
|---|---|---|---|
| 1 | `GET /ui/:uid/federation/:providerId/start` | yes | mints `state`, `nonce`, PKCE verifier |
| 2 | `GET /federation/callback` | **none** | finds everything by `sha256(state)` |
| 3 | `GET /ui/:uid/federation/complete?ref=…` | yes again | same-site redirect, so the strict cookie applies |

Hop 2 → 3 being **same-site and relative** is what restores the cookie. A absolute redirect would not.

Rejected alternatives, recorded so they are not re-proposed: relaxing the interaction cookie to `lax` and
`path: /` (a change to every flow's security properties to serve one), and a per-interaction `redirect_uri`
(no provider will match it, and it cannot be pre-registered).

## Two round-trip records, neither storing its own key

One area, `FederationState`, holds both stages. Stage one is keyed by `sha256hex(state)`, stage two by
`sha256hex(ref)`, and **neither live value appears in any field** — the `PasswordResetChallenge` rule,
applied to both identifiers because a `ref` in a URL is exactly as capturable as a `state`. Expiry is
compared on read as well as reaped, because MongoDB's TTL monitor deletes lazily and a stale handoff is a
sign-in as somebody else.

The area is declared **account-owned** (`byAccount`), and that is a departure from what backlog § 18
anticipated (`unowned`, "it names no principal yet"). The reverse ownership check in
`test/storage_contract/inventory_drift.spec.ts` fails any area whose payload carries `accountId` without
declaring it — correctly, since such a record is one no cascade sweeps — and the handoff stage carries one by
design. `unowned` was therefore unimplementable, and owning it is also the better property: a deleted
account's outstanding handoff dies with it, which `test/storage_contract/federated_links.spec.ts` pins. Stage-one
records carry no `accountId`, are matched by no sweep, and simply expire.

## The decision ladder, and why the order is the contract

`lib/federation/resolve.ts`, in this order:

1. **existing link** → sign in. The link *is* the identity; the email is only how one is established.
2. **email** at the provider's `emailClaim` → absent means refuse; a subject alone matches no human.
3. **domain** allow-list → **before** the collision check. Reversed, it would answer "does an account exist
   for this address?" for addresses the provider is not allowed to speak for.
4. **collision** → link only if `emailTrusted && email_verified === true`. Both halves required.
5. **provisioning** → `jit` creates; `existing_only` refuses.
6. **active**, 7. **verification**, 8. sign in through the same `resume()` a password sign-in uses.

Step 4 is the takeover boundary. `=== true` exactly — a provider that stringifies its booleans does not
clear it. Failing it, the refusal says "sign in with your password": no second account for one address, no
silent takeover.

A provisioned account's password is a hash of 32 bytes discarded on the next line — deliberately not a
sentinel string, which would be a value someone could eventually type.

## Gotchas

### A guarded route's schema is composed, not overridden

`GET /ui/:uid/federation/:providerId/start` has two path parameters under a guard declaring only `uid`. It
answered **422 without ever reaching the handler**: `Property 'providerId' should not be provided`.

Declaring `params` on the *route* does not fix it. This app runs `normalize: false` — an undeclared property
is refused rather than stripped — and the guard's schema is **merged** with the route's rather than replaced.
The fix is `providerId: t.Optional(t.String())` on the `ui` guard itself; optional, so routes without one in
their path are unaffected.

Same family as the audit route's query-parameter gotcha in [[admin-audit-trail]] — *a declared schema on a
request parameter describes what the framework will do with the value* — with the addition that on a guarded
route, "declared" means declared **everywhere the schema is composed**.

### A login page cannot be rendered anywhere but its own URL

`loginClient.tsx` derives both the page name and the interaction id from `window.location.pathname`. A login
document served at `/federation/callback` therefore hydrates into an **empty root** — silently, in a browser
only. The decline path redirects to `/ui/:uid/login?notice=federation_aborted` instead, which also keeps the
provider's `error_description` off the page: an identifier selects a message, it never supplies one. See
[[interaction-page-families]].

### The first gated routes under `/ui`

`alwaysAvailablePrefixes` contains `/ui`, and its comment says the interaction surface is unconditional. The
federation legs are nonetheless gated, and both work because `gatedRoutes` is consulted **before** the prefix
in both `classifyRoutePattern` and `gatedFlagForRequest`. The rule survives intact: with the flag off there
is no provider button and nothing a user could have started, so these are paths that do not exist rather than
paths closed mid-flow.

The consequence for the guard: its coverage assertion was a *sum* of the three classification sets, which
assumed they are disjoint. It is now a union comparison. See [[feature-flag-gating]].

### The management routes are deliberately not gated

A deployment that switches federation off must still be able to **delete** a provider it stopped trusting.
Gating configuration behind the capability it configures would make that provider unremovable.

## What the upstream is trusted for, and what it is not

`jose`'s `createRemoteJWKSet` supplies the whole key-caching contract — TTL, plus one refetch on an unknown
`kid` within its cooldown — so none of it is hand-written; `lib/federation/jwks.ts` adds only a bound on how
many providers are held, because the URL comes from a document an operator edits.
`lib/helpers/jwt.ts` is deliberately **not** extended: it takes this server's own keystore object, so
adapting an upstream key set to that shape would mean writing a second keystore implementation to reach a
verifier jose already exposes.

The upstream's access and refresh tokens are destructured away and never bound to a name that outlives the
exchange. Nothing calls an upstream API, so keeping them would create a secret to leak and a refresh
lifecycle to maintain.

Verification failures answer one uninformative page; the reason goes to the event bus, never to the console —
this route is unauthenticated, so an attacker-triggerable log write is a vector of its own. The reasoning is
[[admin-console-signin]]'s, and it applies here with more force: anyone who can follow a redirect reaches it.

## The masked secret leaked for a year through the bucket routes

`lib/admin/federation/service.ts` states the rule and means it: a provider's `clientSecret` is
write-only, replaced by `SECRET_MASK` "on every read, for every role including super-admin". `present()`
and `presentAll()` are where that happens, and the federation routes have always used them.

The bucket routes did not. A `UserBucket` *contains* its `federation` array, and
`GET /admin/api/buckets` and `GET /admin/api/buckets/:id` returned the document whole — so every
configured provider's client secret went out in plaintext to any authenticated administrator, and the
console's own Buckets page has been receiving them. The exposure was wider than super-admin:
`bucket_get` authorizes with `loadBucketForUsers`, the *broader* check, so a manager of a project merely
backed by the bucket got the secrets too.

Fixed by masking in every bucket projection (`presentBucket` in `lib/admin/buckets/routes.ts`, applied
to list, get, create and update). The shape of the bug is worth remembering more than the fix: an
invariant enforced by a module's own presenter does not survive another module returning the document
that module's data lives inside. Anywhere a nested entity carries a secret, the *containing* entity's
reads need the same presenter.

Found by the MCP surface's secrecy sweep, which iterates every published read rather than the ones
somebody thought to check — see [[admin-mcp-control-plane]]. Two of that sweep's own cases had first to
be fixed for the same class of reason: they asserted a secret was absent while the seed that should have
stored it had silently failed, so the assertion passed on nothing. A negative assertion needs proof its
subject exists.

## Related

- [[interaction-page-families]] — the two families every page here belongs to, and the hydration contract the
  login page's new props must satisfy in both halves.
- [[feature-flag-gating]] — why `gatedRoutes` outranks a prefix, and the coverage assertion that changed.
- [[admin-audit-trail]] — the four rows this added, and why the identity row carries `targetScope`.
- [[deletion-and-revocation]] — links ride the user row, so no cascade arm knows they exist.
- [[account-resolution]] — per-bucket user storage, which is what `findByFederatedIdentity` queries.
- [[self-service-password-reset]] — the digest-keyed-record rule this reuses, and the only route by which a
  provisioned account acquires a usable password.
- [[admin-console-signin]] — the same relying-party discipline pointed at this server's own issuer.
- [[admin-mcp-control-plane]] — the agent surface whose secrecy sweep found the bucket-route leak above.

Verified against [[oauth-server-codebase]] as changed by `specs/022-oidc-federation-login`.
