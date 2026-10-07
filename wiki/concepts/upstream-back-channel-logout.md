---
type: concept
title: 'Upstream back-channel logout: a provider''s sign-out ends the sessions it began here'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-10-07
updated: 2026-10-07
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:global-token-revocation
    - predicate: depends_on
      object: concept:upstream-federation
    - predicate: constrained_by
      object: concept:error-store-capture-sites
---

# Upstream back-channel logout: a provider's sign-out ends the sessions it began here

Spec 073 — item 4b of the SCIM series (issue #62). This server is the relying party of every upstream
provider a bucket federates to, and OpenID Connect Back-Channel Logout 1.0 is how a provider tells its
relying parties that a person signed out of one of its sessions. Keycloak, Auth0 and Ping (PingAM/PingFederate)
send it to a third-party application; Okta, Entra and Google do not (Okta's equivalent is
[[global-token-revocation]]; Entra pushes nothing). A bucket now receives those logout tokens at
`<bucket issuer>/federation/backchannel-logout` and ends the sessions here that came from the upstream session
named — and, through them, every relying party this server signed the person in to.

## Softer than global token revocation, by decision

A logout token reports a sign-out, not a compromise. So each matched session ends exactly as a sign-out here
ends it — `destroyProviderSession` (`lib/shared/destroy_session.ts:73`): relying parties told, grants that do not
outlive a sign-out revoked, **offline access kept** (§2.7), the account untouched. Global token revocation ends
everything; this ends sessions. Keycloak's non-standard `revoke_offline_access` member of `events` (sent when its
administrator chose "Backchannel logout revoke offline sessions") is **ignored** — no vendor-specific branch;
ending offline access is what SCIM deactivation and global token revocation are for.

Which sessions end (`lib/upstream_signals/back_channel_logout.ts:111`):

- **`sid`** → the sessions signed in through that upstream session; with a `sub` too, only if their account is
  the one linked to that `sub` at that provider (a token cannot pair its own `sub` with someone else's `sid`).
- **`sub` alone** → every session of that person whose latest sign-in came through this provider; never their
  password sessions or another provider's.
- Nothing matched → the same `200`, so a provider learns nothing about who signed in here.

## A session now remembers where it came from

Before this, nothing recorded which provider or upstream session a sign-in came through, so there was nothing to
match a logout against. Now:

- The callback reads `sid` from the **verified** ID-token claims (`lib/federation/routes.ts:173`) and carries
  `{ providerId, sid }` through the stage-2 handoff into `result.login.upstream`; a pending link carries it too and
  `settlePendingLink` attaches it when the link lands on the account signing in (`lib/federation/pending_link.ts:59`).
- `resume()` passes it to `Session.loginAccount`, which **replaces or clears** `session.payload.upstream` at every
  sign-in, as it does `transient` (`lib/models/session.ts:273`) — a session re-authenticated by password stops
  answering to the provider. The session stores the provider and a **SHA-256 of the `sid`**, never the value: it is
  the provider's session handle and nothing here needs it back.
- Sessions are reachable only by id, uid and owner, so `resume()` also writes an account-owned
  **`UpstreamSession`** record (`lib/consts/storage_inventory.ts:453`): `sha256("<bucket>:<provider>:<sid>")` →
  account, expiring one session lifetime after the sign-in (`lib/upstream_signals/upstream_session.ts:55`). A token
  naming only `sid` resolves through it to an account whose sessions are then read and filtered. No new adapter
  method was needed — `find`, `upsert`, `findByOwner` exist on all three backends; re-run `db:setup`/`db:setup:pg`.

## The core, generalised once more

The receiver authenticates through `authenticateUpstream` (`lib/upstream_signals/assertion.ts:137`) and inherits
every refusal of [[global-token-revocation]]: asymmetric algorithms only whatever any setting says, the provider's
own published keys, `exp`/`iat`/`jti` required, a five-minute ceiling, single-use `jti` (namespace `bcl:`), opt-in
checked only after authentication. Two things had to become per-format:

- **Where our client id is.** Okta's assertion carries it as `sub`; a logout token's `sub` is the *person* and our
  client id is the `aud`. `UpstreamExpectation.clientIdClaim` (`assertion.ts:65`) says which, declared by the format
  and never guessed — otherwise a token could choose the provider it is judged against. `aud` must be one value.
- **Format claim rules**, run after the signature and lifetime and before the `jti` is spent
  (`assertion.ts:228`): the back-channel-logout event as an object, no `nonce` (what tells a logout token from an ID
  token), a `sub` or a `sid` (`back_channel_logout.ts:68`). `typ` may be absent, `JWT` or `logout+jwt`.

## 400 for everything, and the fault still recorded

§2.8 requires `400` for an invalid request *and* for a logout that failed. So: refusals → `400
{"error":"invalid_request"}` with one body whatever the check; unreadable provider keys → `400
temporarily_unavailable`; a fault while ending sessions → `400 logout_failed`, **recorded in the error store at 500
where it is answered** (`back_channel_logout.ts:188`) — the precedent of a fault delivered by redirect, and the fifth
[[error-store-capture-sites]] site. The one non-400 is the failed-credential limit (`429` + `Retry-After`): a
request it refuses was never judged. Operators see `upstream.logout.success {bucketId, providerId, ended}` and
`upstream.logout.refused {bucketId, providerId?, reason}` ([[event-bus]]), never the `sub` or `sid`. Not audited:
it relays a person's own sign-out, which is not audited either, and arrives on every routine sign-out.

## Gating and administration

The route is gated by `federation.enabled` (`lib/consts/route_classification.ts:235`), not a flag of its own:
Back-Channel Logout 1.0 is final, so there is no deviation to isolate, and with federation off nothing signed in
through a provider. The opt-in is the provider option `acceptsBackChannelLogout` (`lib/federation/types.ts`), off
on every provider stored before it, settable only for an OIDC provider; the console shows the address to register
(`lib/admin/federation/service.ts:91`) with the help text, and MCP `federation_provider_update` carries it because
its arguments derive from the schema.

## Verified against a real Keycloak

On 2026-10-07 against Keycloak 26.8.0 behind a public HTTPS name (a throwaway stand on the owner's home server,
removed afterwards): a federated sign-in recorded `session.upstream` and an `UpstreamSession` record; signing out in
Keycloak's own logout screen made Keycloak post a logout token, answered 200, and the session ended — with "Backchannel
logout session required" on (`sid`) and off (`sub` only). The run first failed earlier, at sign-in: Keycloak adds
`session_state` to every return and the callback refused undeclared parameters — see [[upstream-federation]].

## Accepted limits

- **Sessions signed in before the upgrade** carry no origin and no logout reaches them; they end at expiry.
- **A session kept alive more than 14 days after its federated sign-in** outlives its `UpstreamSession` record, so a
  `sid`-only token misses it. Tokens with `sub` — every one Keycloak, Auth0 and Ping send — still reach it.
  Refreshing the record on every session save would double federated session writes to close a gap no known
  provider opens.
- **A sign-in in flight** (ID token issued, session not yet written) is not ended by a logout that lands in between.
- **One upstream application per bucket**: a provider registers one logout URL per application, so an application
  reused across buckets is heard only by the bucket at that URL; a bucket's address change changes the URL.
- **Keycloak older than 24.0.0** (except 22.0.8 and 23.0.4) sends logout tokens with **no `exp`**
  (keycloak/keycloak#25753) and is refused; fixed releases send `exp = iat + 120`.
