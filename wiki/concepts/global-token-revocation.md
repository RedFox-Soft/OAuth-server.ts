---
type: concept
title: 'Global token revocation: an upstream provider ends a user''s access here'
tags: [architecture, contract, gotcha, oauth, config]
sources: [oauth-server-codebase]
created: 2026-10-07
updated: 2026-10-07
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:end-user-lifecycle
    - predicate: depends_on
      object: concept:upstream-federation
    - predicate: depends_on
      object: concept:admin-audit-trail
---

# Global token revocation: an upstream provider ends a user's access here

Spec 072 — the first slice of part 4 of the SCIM series (issue #62, item 4a). A bucket's upstream identity
provider, opted in, sends one signed request and everything a user it names holds here ends: sessions, refresh
tokens, opaque access tokens, grants, with relying parties told by back-channel logout. The account is **not**
deactivated — the user signs in again straight away and consents afresh. This is what Okta sends as
**Universal Logout**.

## Built on an expired draft, on purpose

The governing text is draft-parecki-oauth-global-token-revocation-06 (2026-02-24). It is an *individual* draft
that **expired unadopted on 2026-08-28**; the OAuth WG never adopted it and no `draft-ietf-…` exists. It is
built anyway because, as researched on 2026-10-07, it is the only server-side "end everything" any major
workforce IdP sends to a generic application — Okta, under its Identity Threat Protection licence. Entra sends
nothing at all to a third-party client (no back-channel logout, no external Shared Signals; continuous access
evaluation is Microsoft-only); Google sends only RISC for consumer accounts; Ping, Auth0 and Keycloak send OIDC
Back-Channel Logout, received since spec 073 (#62 4b, [[upstream-back-channel-logout]]). Among 16 peer products only Auth0 receives this request,
in the same shape: one endpoint, the IdP's own keys, `iss_sub`.

Three hedges follow from building on it:

- **The target is Okta's documented request, not the draft as a standard.** Okta's `typ` is
  `global-token-revocation+jwt`, its `iss` the organisation, its `sub` our client id there, a not-before five
  minutes back and an expiry five minutes ahead.
- **Everything sits behind `globalTokenRevocation.enabled`, off** (`lib/configs/application.ts:272`), whose
  console text says the draft expired. Discovery names the draft revision as the "registrar" of its two members
  (`lib/configs/discoverySupport.ts`), because they were never IANA-registered.
- **The format is one module over a format-neutral core** — next section.

## One core, many formats

`lib/upstream_signals/` holds the request "an upstream provider of this bucket asks to end a user's access"
separately from any wire format. `authenticateUpstream` (`lib/upstream_signals/assertion.ts:137`) decides who may
ask and how they are authenticated; `resolveReachableUser` (`lib/upstream_signals/subject.ts:22`) decides whom
they may name; `endAccessForUpstream` (`lib/upstream_signals/end_access.ts`) ends it. The GTR plugin
(`lib/upstream_signals/global_token_revocation.ts`) supplies only which claim carries our client id (`sub` here), its
audience, accepted `typ`s, replay namespace and the provider option that admits it. Inbound back-channel logout is
the second such file since spec 073 (`lib/upstream_signals/back_channel_logout.ts`, [[upstream-back-channel-logout]]),
which made the client-id claim per format (`clientIdClaim`, a logout token carries it as `aud`) and added a
per-format claims check; a CAEP `session-revoked` event would be a third and inherits every refusal below.

## The refusals are the feature

An endpoint that ends sessions is a denial-of-service lever over a whole workforce, and the inputs an attacker
needs — the provider's issuer, our client id there, a user's upstream subject — are not secrets. Keycloak's
**CVE-2026-18569** (2026-08) is the cautionary case: its back-channel logout receiver accepted `alg: none` logout
tokens for a provider whose signature validation an operator had switched off. So:

- **No setting can relax verification.** Asymmetric algorithms only, a constant
  (`assertion.ts:46`) intersected with what the provider advertises; `none` and `HS*` are refused whatever any
  provider, bucket or instance field says.
- **The provider is found by (issuer, client id) as two values** (`assertion.ts:95`), never a composed key —
  Keycloak #42209 broke brokered logout with a dot in a provider alias.
- `aud` exactly the endpoint; `exp`, `iat`, `jti` required; lifetime ≤ 300 s measured as `exp − iat` and
  `exp − now` (`assertion.ts:37`). **`nbf` never counts toward the lifetime** — Okta's `nbf` is five minutes in the
  past, so `exp − nbf` is ten minutes and would refuse every real request.
- `jti` single-use through `ReplayDetection` under `gtr:<bucket>:<provider>:` (`assertion.ts:236`). The trailing
  `:` matters: the replay id is `sha256(namespace + jti)` with no separator of its own.
- A disabled or not-opted-in provider is refused **403 only after authentication** (`assertion.ts:244`).
- A user the provider may not name and a user who does not exist get the **same 404** body; the reason goes only
  to `upstream.revocation.refused`.
- A failed credential is charged at the strict per-origin rate, on a counter shared with SCIM
  (`lib/helpers/unauthenticated_charge.ts`).

### Two key caches for one provider

`keySetFor` (`lib/federation/jwks.ts`) switches jose's cooldown **off**, because on the sign-in path only the
provider can present an unknown `kid`. Here anyone can, and a cooldown-free cache would refetch the provider's
keys on every request carrying a random `kid`. `presentedKeySetFor` (`jwks.ts:64`) is a second cache with
jose's default 30 s cooldown. A rotation is honoured once per cooldown; the rotation test advances the clock
past it.

## Whom a provider may name

Those it signs in (a `federated` link to it) and those its bound provisioning connection provisioned
(`subject.ts:22`). `iss_sub` resolves through the link and requires `iss` to be the caller's own issuer (another
issuer is a 400: nobody could be named); `email` matches case-insensitively and then checks reachability. A
provisioned user who never signed in through the provider has no link, so only `email` reaches them.

## Audited under "sign out everywhere"

The audit table admits only actions backed by a mounted `/admin/api` route
(`test/admin/audit_route_classification.spec.ts`), so the upstream request needed a real action rather than a
second audit mechanism. It got one that administrators lacked anyway: **"sign out everywhere"**
(`POST /admin/api/buckets/:id/users/:uid/sign-out`, `lib/admin/users-end/routes.ts:270`; MCP
`bucket_user_sign_out`, ordinary), backed by `revokeEndUserAccess` (`lib/end_users/service.ts:318`). The upstream
request records the same `enduser.signout` through `recordUpstreamAudit` (`lib/admin/audit/record.ts:153`):
actor `upstream:<bucketId>:<providerId>`, **`viaSurface: 'upstream'`**, target the user, never the identifier the
provider named them by.

**Gotcha: a new `viaSurface` literal touches five places.** The entry schema union — which MongoDB and PostgreSQL
validate *on read*, so forgetting it breaks the audit list on real databases while `bun test` stays green — the
Mongo surface filter, `write()`'s input type, the console's audit page, and the MCP `audit_list` summary.

## What it does not reach

A JWT access token a resource server validates locally lives to its expiry — the known limit of
[[end-user-lifecycle]]. IPSIE SL2 allows 15 minutes for unbound tokens (60 for DPoP-bound), so a bucket that
claims SL2 sets short JWT access-token lifetimes. Sweeping grants goes beyond the draft's MUST (refresh tokens
and re-authentication); the draft permits it, and one access-ending operation for every path was the #62 decision.

## Open before calling it stable

Not yet run against a real Okta organisation. Okta documents `sub` as "client_id/appInstanceId", and `iss` as
the org or custom-domain base URL — a provider configured with a custom authorization server issuer
(`…/oauth2/default`) may then not match. The fallback, if needed, is an optional per-provider revocation issuer;
it is not built speculatively.

## Related

- [[end-user-lifecycle]] — the access-ending operation this calls.
- [[upstream-federation]] — the provider record, its option, and the sign-in key cache.
- [[scim-provisioning]] — the connection whose users a provider may also name, and the deprovisioning guard.
- [[admin-audit-trail]] — the route-backed action rule and the surfaces.
