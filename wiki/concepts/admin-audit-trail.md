---
type: concept
title: 'The admin audit trail'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-03
updated: 2026-08-25
graph:
  node_type: concept
---

# The admin audit trail

Every state-changing action in the administrative control plane writes exactly one append-only record
naming who did it, what they did, which entity it affected and when. The constitution requires this of
*every* admin action, human- or MCP-initiated, and 27 mounted routes are subject to it. The trail is
permanent: the storage area declares no expiry, the store interface exposes no update or delete, and no
product surface offers either (`lib/adapters/types.ts`, `lib/consts/storage_inventory.ts`).

## Audit-first, and authorization-first — the order is not interchangeable

The record is written **before** the mutation it describes, and a failed write aborts the request, so a
change can never be applied without a record (`lib/admin/audit/record.ts`). The write also happens
**after** authentication and authorization, and both halves are load-bearing:

- Audit-first is why the entry precedes the change. Recording afterwards would leave a window where a
  mutation is applied and the record fails.
- Authorization-first is why the call sits inside the handler rather than in a route-level plugin. The
  admin handlers authorize in their own bodies (`assertAuth`, `assertRole`, `assertBucketAccess`,
  `loadManageableProject` in `lib/admin/auth/rbac.ts`), so a plugin on `onBeforeHandle` would run
  before anyone is known to be authorized — turning `/admin/api/*` into an unauthenticated write path
  into permanent, never-expiring storage. That is a storage-growth and trail-poisoning vector, not
  merely noise.

A tempting-looking refactor — "move the 23 calls into one plugin so nobody can forget" — therefore
trades a completeness problem for a security one. Completeness is instead guaranteed by a table and a
drift guard (below).

**An entry means an authorized actor reached the point of applying the change — not that the change
took effect.** A not-found, a uniqueness conflict, or the last-super-admin guard can still follow a
written entry. The admin UI states this above the trail, because a reader who assumes otherwise will
read a refused request as a completed one.

## The table is load-bearing

`lib/consts/admin_audit_routes.ts` enumerates all 27 audited routes with their action name and target
type, plus the single deliberate exclusion (`POST /admin/api/logout` — session lifecycle, not a change
to a managed entity). It is not documentation:

- `recordAdminAudit` takes an `AuditAction` — the union of the table's `action` values — so an action
  the table does not declare cannot compile at the call site.
- `targetType` is resolved *from* the table, never passed by the caller, so it cannot be mistyped.
- `test/admin/audit_route_classification.spec.ts` compares the table against `elysia.routes` in both
  directions: a new mutating admin route with no entry fails and is named, and a row for a route the
  server does not serve fails too.

Same shape as [[feature-flag-gating]]'s route classification and the storage inventory, and for the
same reason: forgetting is the failure mode, so forgetting has to fail the suite. The module imports
nothing — anything transitively importing `lib/adapters/mongodb/db.ts` connects at module scope and is
unloadable under test.

## Names, not values

An entry carries the **names** of the fields a request set (`attributes`) and never their values. This
makes secret-freedom structural rather than a redaction rule a future call site can forget: a mail
settings change records `password` as a name, and the password itself cannot be anywhere near the
trail. `enduser.password.reset` records no field names at all — the action name already says
everything, and the value must not be recorded.

Two naming rules worth keeping:

- `admin.deactivate`, not `admin.delete`: `DELETE /admin/api/admins/:id` sets `active: false` and keeps
  the row. A trail that says "delete" for a deactivation is a false statement an investigator acts on.
- `bucket.update` covers the whole update. It replaced `bucket.settings.update`, which fired only when a
  registration or verification field was present — so renaming a bucket or reassigning its managers left
  no trace. Historical entries keep the old name and stay filterable, because the action filter matches
  recorded values rather than a fixed enum.

## Only the names that moved, and nothing at all when nothing moved

`attributes` names the fields whose value actually **changed**, not the fields a request happened to
carry. The distinction is invisible on a hand-built request and decisive on a real one: both settings
surfaces are full replaces — the server-settings page submits the whole catalogue on every Save
(`lib/admin/ui/pages/Settings.tsx`) and the mail card all seven of its fields — so recording the
submitted keys meant almost every entry said *everything changed*, which is indistinguishable from
saying nothing. Both routes now diff the submission against the values in force and record only the
difference (`lib/admin/settings/routes.ts`, `lib/admin/settings/smtp/routes.ts`).

A submission that changes nothing is therefore **not an event**: no entry, no write, a 200 carrying
the current state. This does not weaken the completeness rule above — an entry still precedes every
mutation — it narrows what counts as one. The trail is a record of changes, and an entry for a change
that never happened is a false statement an investigator acts on, the same reasoning behind
`admin.deactivate` not being called `admin.delete`.

Three consequences to keep in mind:

- A key the catalogue does not know has no value in force to be compared against, so it is never
  filtered as "unchanged" — it stays in the submission and `validateValue` refuses it. Dropping it
  would turn an unknown setting into a silent 200 that applied nothing.
- The mail password is unaffected by design: the masked sentinel resolves to the stored secret before
  the comparison, so keeping it simply is not a change, and only ever its *name* can reach the trail.
- Tests that pin an entry's field list must establish their own baseline (`configStore.set({})`, a
  seeded SMTP record). Otherwise overrides left by an earlier spec in the same process decide which
  keys the entry names — and spec order differs by OS, so the failure is CI-only.

## Creations allocate their id before recording

A creation has no identifier to name until it exists, which collides with audit-first. Every creating
route therefore allocates the id itself and passes it to the store: `projectStore.create` and
`userBucketStore.create` already accepted an optional `_id`, and `UserStoreInstance.create` and
`createClient` gained one. No per-operation exception to audit-first, at the cost of two signature
changes.

## Per-bucket targets need their bucket

End-user records carry `targetScope` — the bucket id — because those users live in per-bucket
collections and `getUserStore(bucketId)` needs the bucket to resolve anyone. Without it an `EndUser`
entry names an opaque id that cannot be turned into an account, or even an email, without searching
every bucket. It is a separate field rather than a composite `targetId` so exact-match retrieval on a
bare user id keeps working. These routes are the only ones that set it — four end-user operations plus
`federation.identity.delete`, which severs one account's upstream link; see [[account-resolution]] for how
per-bucket user storage works.

## Gotcha: Elysia strips undeclared query parameters before validation

`GET /admin/api/audit` rejects an unknown query parameter by checking the raw URL
(`lib/admin/audit/routes.ts`), not via the route schema. Elysia lifts only *declared* keys out of the
query string, so an undeclared one never reaches the schema and `additionalProperties: false` cannot
refuse it — measured, not assumed. This matters more here than on most endpoints: a mistyped filter
that is silently dropped answers with the **unfiltered** trail, a wrong answer wearing a 200, on the
one surface whose entire purpose is to be trusted about what happened.

Same family as the coercion-contract gotcha in [[rich-authorization-requests]]: a declared schema on a
request parameter describes what the framework will *do* with the value, not what it will refuse.

## Reading the trail

`GET /admin/api/audit` is super-admin only, newest-first, offset-paged, and filterable by actor (id
**or** email), action, target type, target id, scope and an inclusive time window. Ordering is
`(timestamp desc, _id desc)`: `_id` is unique, so the order is total, which is what stops a page
boundary from dropping or repeating an entry when two actions land in the same millisecond. A backwards
window is refused with 422 rather than answered with an empty page — an empty page is
indistinguishable from "nothing happened", the one answer an audit trail must never give by accident.

## Related

- [[deletion-and-revocation]] — a cascade is an effect of the already-recorded delete, and per-area counts stay out of the trail because a count is a value.
- [[admin-plane-error-shape]] — the other admin-plane contract a standalone mount cannot verify.
- [[feature-flag-gating]] — the declarative-table-plus-drift-guard pattern this reuses.
- [[account-resolution]] — per-bucket user storage, which is why `targetScope` exists.
- [[rich-authorization-requests]] — the other place a framework's schema handling behaved differently
  than reading it suggested.
- [[client-identity-from-database]] — client records are what several of these operations mutate.
- [[admin-console-signin]] — how the actor named in every entry is established, and the same
  authorization-before-write reasoning applied to an unauthenticated route.
- [[upstream-federation]] — the four rows it added, and why a provider's `targetType` is the bucket that
  holds it rather than the provider itself.

Verified against [[oauth-server-codebase]] as changed by `specs/016-admin-audit-completeness`.
