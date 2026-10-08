---
type: concept
title: 'End-user lifecycle: ending access, the local lock, provisioned users'
tags: [architecture, contract, gotcha, oidc]
sources: [oauth-server-codebase]
created: 2026-10-06
updated: 2026-10-08
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:deletion-and-revocation
    - predicate: depends_on
      object: concept:account-resolution
---

# End-user lifecycle: ending access, the local lock, provisioned users

Spec 069 — part 1 of 4 of SCIM provisioning. It added no protocol surface; it made deactivation actually
end access, gave the user record a provisioned identity, and moved every rule about changing an end user
into one service so the admin API today and provisioning tomorrow obey the same ones.

## Deactivation used to revoke nothing

Before 069, `active: false` was enforced only lazily, at the next account resolution
([[account-resolution]]): sign-in, refresh, device and CIBA were refused, but every session stayed alive,
an opaque access token answered `active: true` at introspection until it expired, and no relying party was
told. An administrator responding to a compromised account had no way to end access *now*.

Now deactivation, the local lock and deletion all run `revokeAccountAccess`
(`lib/end_users/revoke_access.ts:51`) — and, since spec 072, so does **"sign out everywhere"**
(`revokeEndUserAccess`, `lib/end_users/service.ts:318`), which ends access without writing any flag, for an
administrator and for a bucket's upstream provider through [[global-token-revocation]] — in this order:

1. The caller has already written the flag, so account resolution refuses the user from that moment.
2. **Back-channel logout for every session** (`notifyRelyingParties`, `revoke_access.ts:17`). Sessions are
   read *before* the sweep because a logout token carries the session's `sid`, and the session record is
   the only place that holds it. Reading needed a new adapter method, `findByOwner` — until then the only
   way to enumerate a principal's records was to destroy them (`destroyByOwner`). Delivery failures never
   stop the operation; they surface as `backchannel.error`, as on a full sign-out.
3. **Sweep every account-owned area** (`sweepAccountOwned`, `lib/helpers/cascade.ts:134`), derived from
   the inventory's owner declarations, so an area added later is included by construction — the same
   engine as [[deletion-and-revocation]]. Email-addressed areas (login and reset throttles) are *not*
   swept: they are rate limits, not access, and clearing a login throttle on an account under attack
   would reset the brute-force counter mid-incident.

Introspection needed no change: it already answers `active: false` once the grant behind a token is gone
(`lib/actions/introspection.ts:134`).

**Reactivation restores nothing.** Grants are swept, so consents go with them; the user signs in and
consents afresh. IPSIE requires "all access mechanisms and authorizations" to be deactivated.

**The one thing this cannot reach** is a JWT access token a resource server validates locally — it lives to
its own expiry: the declared resource's `accessTokenTTL`, which a declaration that names none stores as 900 s
(`lib/adapters/mongodb/protectedResourceStore.ts:66`, the same in the other two stores) and an administrator may
raise to a day (`lib/admin/resources/schema.ts:23`). IPSIE SL2 allows 15 minutes for tokens not bound to a key, so
the default meets it and a raised value does not. (Corrected 2026-10-08: this said "1 h by default", which is
`ttl.AccessToken`'s fallback in `lib/configs/liveTime.ts:47` for a token with no declared resource — and such a
token is opaque, so it never reaches a resource server to be validated locally.)

### A partial sweep answers 500, not an audit detail

The obvious design — put the sweep report in the audit entry — is impossible: the entry is written
*before* the change ([[admin-audit-trail]]) and the trail is append-only. So a deactivation or lock whose
sweep left an area answers `500` with `failedAreas`, exactly as clearing an authenticator and deleting a
user already did. The user is unable to sign in either way, and deactivating again sweeps again — which is
why re-deactivating an inactive user is allowed rather than a no-op.

## One predicate decides whether a user may sign in

`canSignIn` (`lib/end_users/can_sign_in.ts:11`) — `active && !lockedLocally` — is used by account
resolution (`lib/addon/account.ts:61`), the password door (`lib/interactions/index.ts:817`), the federated
door (`:1202`), federation linking and provisioning, and both password-reset steps. Two copies of "is this
user allowed" drift, and the drifted one is the door a locked user walks through.

## The lock is not `active`

`active` belongs to whoever manages the user — an administrator for a local user, the provisioning
connection for a provisioned one. A local deactivation of a provisioned user would be undone by that
connection's next sync (`active: true`), so it cannot be the emergency control. `lockedLocally` is a
separate field that only the admin routes (and MCP through them) set or clear
(`lib/end_users/service.ts:301`, `:317`); nothing a connection sends reaches it.

This is a **deliberate departure from IPSIE AL2**, which forbids local changes to identity-service-managed
users. It touches sign-in only, never the profile, and exists because an incident response must not wait
on an external system. `bucket_user_unlock` is `high` in the MCP catalogue — it re-admits an account an
administrator judged compromised — while `bucket_user_lock` is `ordinary`, like deactivation.

## Provisioned users are read-only here

A user with `provisionedBy` set belongs to that connection. An administrator's update, password reset or
delete is refused with 409 naming the connection, before the audit write, so a refusal leaves no entry
(`assertActorMayChange`, `service.ts`). A connection reaches only its own users; another connection's, or
a local one, answers 404 to it. Clearing an authenticator stays allowed — it is account recovery, not a
profile edit.

**Why `provisionedBy` and not `managedBy`.** `managedBy` is the name of a retired ownership field (the
manager list that group ownership replaced). A new field with the old name would have read as that field
come back. (Until 2026-10-06 a guard, `test/admin/retired_migration.spec.ts`, failed on the identifier
anywhere in code; it was removed under Principle V — it tested that removed code stayed removed, which no
audience depends on.)

## Uniqueness rides on derived scalar keys

`userName` is unique per bucket **case-insensitively**; `externalId` is unique **per connection**
(RFC 7643 §3.1 scopes it to the provisioning domain). Both are stored exactly as sent, and beside them
the store keeps a derived key (`lib/adapters/end_user_keys.ts`) that the unique indexes hold
(`lib/consts/storage_inventory.ts:255-256`):

- `userNameKey` — NFC-normalised lowercase. A collation would behave differently on MongoDB and PostgreSQL
  and need a divergence entry; a stored key is plain equality on both.
- `externalIdKey` — `` `${provisionedBy}:${externalId}` ``. The obvious compound `{ provisionedBy,
  externalId }` index cannot be made correct with `sparse`: MongoDB indexes a compound sparse index for
  any document holding *either* field, so two users of one connection without an identifier collide on
  `(connection, null)`. That needs a `partialFilterExpression`, which `IndexSpec` deliberately does not
  model — the same trade-off the federated-identity index records. A single scalar needs only `sparse`.

The keys never leave the server (`presentUser` strips them) and are never accepted from a caller; the store
recomputes them on every write that touches an identity field. `database/verify_end_user_identity.ts`
proves the indexes against real MongoDB and PostgreSQL, including the race for one external identifier.

## Profile → claims is this server's own table

No specification maps SCIM attributes to OIDC claims. The table lives in `lib/consts/profile_claims.ts`
(`userName` → `preferred_username`, given/family/middle name, `nickName`, `locale`, `timezone` →
`zoneinfo`, primary phone → `phone_number`) and is merged in `findAccount` *before* the stored `claims`,
so an administrator's claim still wins (`account.ts:84`).

**Gotcha found while planning:** the default claims setting mapped no `profile` or `phone` scope, so no
profile claim — including ones an administrator stored — reached a token on a default instance. The default
now carries the OIDC Core §5.4 lists; an instance that saved its claims setting keeps what it saved, because
the stored object replaces the default whole (the same trap [[amr-reporting]] records).

## Related

- [[deletion-and-revocation]] — the cascade engine this reuses, and the three operations it distinguishes.
- [[account-resolution]] — where `canSignIn` is enforced on every token issuance.
- [[admin-audit-trail]] — why the sweep report cannot be in the entry.
- [[upstream-federation]] — the sign-in path provisioned users use, through the correlation step part 2 added.
- [[scim-provisioning]] — part 2 (spec 070): connections now exist, write through this service as the
  `connection` actor, and `createEndUser` writes the identity fields in one insert (it used a follow-up
  update, which left a half-made account behind whenever that update collided).
