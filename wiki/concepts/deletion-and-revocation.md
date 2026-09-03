---
type: concept
title: 'Deletion and revocation'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-05
graph:
  node_type: concept
---

# Deletion and revocation

Three different operations are easy to confuse, and the code has always distinguished them:

| Operation | What it destroys | What it leaves |
|---|---|---|
| **Protocol revocation** (RFC 7009, end-session) | every token under one grant | the `Grant` record — the consent itself |
| **Principal deletion** (client, end-user) | the principal, then every record naming it as owner, including its grants | nothing of that principal |
| **Container deletion** (project, bucket) | nothing — it is *refused* while occupied | everything, until the operator empties it |

"Revoke" reads as "remove everything" and the code disagrees. A grant is the record that a user
authorized a client; revoking a token is not withdrawing that authorization, so only a principal cascade
destroys grant rows (`lib/helpers/revoke.ts`, `lib/helpers/cascade.ts`).

## The visible half of client deletion was already fixed; the invisible half was not

`tryFindClient` reads `adapter('Client')` on every call and the validation memo is keyed by a hash of the
stored properties (`lib/models/client/validate.ts`), so a deleted client cannot authenticate — instantly,
with no cache to wait out. See [[client-identity-from-database]].

Every token it had already issued kept working to its own TTL. An operator watching the client fail to
authenticate reasonably concluded the deletion had taken effect. **A half-working guarantee is more
dangerous than a missing one**, which is why the cascade exists.

## Ownership is declared as data, and read by one engine

`lib/consts/storage_inventory.ts` gives every storage area an `owners` block: the payload field naming
its owning account, the field naming its owning client, or an explicit `none` **with a reason**.
`lib/helpers/cascade.ts` filters that table; no call site names a collection.

The reason is specific rather than stylistic. **A hand-written cascade fails silently the first time an
area is added** — the new area's records simply outlive their principal and nothing says so. Same shape
as the route classification in [[feature-flag-gating]] and the audited-route table in
[[admin-audit-trail]], under the same two-way drift guard
(`test/storage_contract/inventory_drift.spec.ts`).

### Two areas a grant walk cannot reach

Collecting a principal's grant ids and calling `revokeByGrantId` looks equivalent and is not:

- **`ClientCredentials` carries no `grantId` at all** — a machine-to-machine token belongs to a client
  with no user and no consent, so a grant walk misses it entirely.
- **`RegistrationAccessToken` may be issued with no expiry.** Confirmed by inspection: a saved record is
  `{ jti, kind, clientId, iat }` — no `exp`. It is therefore the only swept area whose residue after a
  partial failure is *unbounded*, which is why the cascade sweeps it **first**.

Both are easy to forget and neither announces itself. Sweeping by owner field reaches both.

### The ordering trap that fails in silence

`VerificationResend`'s id **is** `${bucketId}:${email}`, and nothing else records the email. So the
account cascade must read the user's email **before** destroying the account row. The obvious ordering —
destroy, then cascade — skips that record, leaves no error anywhere, and looks correct in every test that
does not assert it specifically. `cascadeForAccount` takes the already-computed id rather than the bucket
and account precisely so the ordering is visible in its signature.

This turned out to be a pattern rather than a one-off. `PasswordResetThrottle`
([[self-service-password-reset]]) is keyed identically, so the parameter was renamed from
`verificationResendId` to `emailScopedId` and the engine now destroys that id across a small list of
email-scoped areas — the area names staying in the engine, as every other area name does. A second
parameter per area would have duplicated the ordering hazard; the third such area needs no signature change.

## `revokeByGrantId` meant two different things per adapter

- **Mongo**: `deleteMany({'payload.grantId': id})` — only its own collection.
- **Memory, before**: deleted *every* key tracked under `grant:<id>` and dropped the index. So the first
  of `revoke()`'s five calls wiped all five areas and the other four no-op'd against a missing index.

A per-model method that deletes another model's records is a contract its name and its receiver both
deny. Memory now filters the index by its own `${model}:` prefix — cheap, because the index has always
stored full model-prefixed keys (`lib/adapters/memory/memoryAdapter.ts`).

### The grant-type filter was reading the wrong client

`revoke()` used to ask `client.grantTypeAllowed(...)` before sweeping each area. Two defects in one:

1. Narrow a client's grant types *after* issuance and its refresh tokens survived revocation on Mongo —
   and not on memory, where the first call wiped everything regardless. A live behavioural divergence.
2. On the end-session path, `oidc.client` is the **logout-initiating** client
   (`lib/actions/end_session.ts`), applied to *every* authorization in the session. The filter consulted
   an unrelated client's grant types to decide another client's tokens' fate.

The filter only ever saved four no-op deletes. `revoke(grantId)` now takes the grant id alone.

## Containers guard; principals cascade. The line is visibility

An operator can see and name a project's clients, so refusing tells them exactly what they are about to
destroy and keeps one audit entry per entity destroyed. Nobody can be asked to enumerate the tokens a
client issued, least of all during an incident.

- A project refuses deletion while any id in `clientIds` still **resolves** via `Client.tryFind`. An
  unresolvable id must never make a project permanently undeletable — and a refused request prunes
  nothing, because **a conflict changes nothing at all**, audit entry included.
- A bucket refuses while any user exists, **including `active: false` accounts**: deactivation is a
  sign-in decision, not absence.
- An assigned bucket is not a blocker on its own. Buckets are shared and outlive projects.

A refusal answers 409 with `blockers: [{ kind, count, ids? }]`. Client ids are listed; end-user blockers
carry a **count only** — a bucket can hold thousands of accounts and their identities are not the
caller's business.

## Deliberately left behind

Each recorded in code rather than left implicit:

- **`Session.authorizations[clientId]`** survives client deletion. No index reaches into a sub-document,
  and the entry is inert: `lib/models/base_token.ts` compares a token's `grantId` against
  `session.grantIdFor(clientId)`, which now resolves to a destroyed grant.
- **Admin operator sessions.** Admin deletion deactivates rather than destroys.
- **Bucket-scoping of the account sweep.** An `accountId` is a `nanoid`, globally unique, and tokens
  record no bucket — so a second predicate would exclude nothing.

## A partial failure is answered, not undone

Order is audit → destroy the principal → cascade. A sweep that fails partway therefore leaves the
principal gone, answers `500` with `failedAreas`, and a repeated `DELETE` answers `404`. That is the
accepted cost of closing the door first, and the residue is bounded by each area's TTL *because* the one
unbounded area goes first.

## Federated links need no cascade arm

An account's upstream identities are embedded on its user row (`User.federated`), so destroying the row
destroys them, and destroying a bucket's area destroys every row in it. No arm of the cascade mentions the
field, and none needs to — which is the reason the alternative, a links area of its own, was rejected. The
one thing the cascade *does* reach explicitly is an outstanding federated handoff, and only because the
`FederationState` area declares `accountId` as its owner. See [[upstream-federation]].

## Related

- [[client-identity-from-database]] — why a deleted client cannot authenticate on the very next request.
- [[admin-audit-trail]] — audit-first ordering, and why per-area counts stay out of the trail: the rule
  is field names, never values, and a count is a value.
- [[feature-flag-gating]] — the declare-a-table-and-guard-the-drift pattern this is the fourth use of.
- [[token-payload-access-contract]] — owner fields live under `.payload.*`, which is what the sweep
  queries.
- [[admin-plane-error-shape]] — how the 409 body reaches the caller intact.
- [[upstream-federation]] — embedded links, and the round-trip area whose ownership declaration is what
  makes a mid-flight handoff sweepable.
