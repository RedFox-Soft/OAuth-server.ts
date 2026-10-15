---
type: concept
title: 'The admin audit trail'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-03
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:admin-console-signin
      source: oauth-server-codebase
      evidence: "lib/admin/audit/record.ts:68 names the actor from the resolved admin context and nowhere else: 'actorId: ctx.userId, actorEmail: ctx.email'."
      confidence: high
      status: current
    - predicate: constrained_by
      object: concept:team-ownership
      source: oauth-server-codebase
      evidence: "lib/admin/audit/routes.ts:230 scopes the read by owning team (stored as ownerGroupId), a super administrator excepted: 'const ownerGroupIds = ctx.superAdmin ? ...', spread into the query at line 277."
      confidence: high
      status: current
---

# The admin audit trail

Every state-changing action in the administrative control plane writes exactly one append-only record
naming who did it, what they did, which entity it affected and when. The constitution requires this of
*every* admin action, human- or MCP-initiated, and every mounted mutating route is subject to it (91 since
spec 089 added the invitation, mark-verified, per-application sign-out and four bulk routes — a bulk route writes
one `enduser.bulk.<act>` entry per person — and an entry may carry `clientId`; 84 after spec 090; 27 when this page
was written). The trail is
permanent: the storage area declares no expiry, the store interface exposes no update or delete, and no
product surface offers either (`lib/adapters/types.ts`, `lib/consts/storage_inventory.ts`).

Since 2026-10-06 the trail also records an actor that is not a person: a SCIM provisioning connection, as the
sentinel `connection:<id>` (the bootstrap's convention — a `:` and no `@`), with `viaSurface: 'scim'` and the
project's `ownerGroupId` so that the project's team sees it (`recordConnectionAudit`,
`lib/admin/audit/record.ts`). It reuses the `enduser.*` actions; the console's audit page filters by
surface. See [[scim-provisioning]].

Since 2026-10-07 (spec 072) there is a third non-person actor: a project's upstream identity provider ending a
user's access through global token revocation, recorded as `upstream:<bucketId>:<providerId>` (the stored
project id) with
`viaSurface: 'upstream'` (`recordUpstreamAudit`). It needed a route-backed action, because the table admits no
other; it records the action of the new administrator operation "sign out everywhere", `enduser.signout`.

Since spec 095 the fourth: an end user removing an application's access from their own connected-apps page,
recorded as `enduser:<bucketId>:<accountId>` with `viaSurface: 'self-service'` under the administrator's
`enduser.application.signout`, with the project's `ownerGroupId` (`recordEndUserAudit`,
`lib/admin/audit/record.ts:222`). The read resolves the person's address as `actorName`. See
[[connected-apps-page]].
**A new surface literal touches five places** — the entry schema union (validated *on read* by MongoDB and
PostgreSQL, so a miss breaks the audit list in production while `bun test` stays green), the Mongo surface
filter, `write()`'s input type, the console audit page and the MCP `audit_list` summary. See
[[global-token-revocation]].

## Audit-first, and authorization-first — the order is not interchangeable

The record is written **before** the mutation it describes, and a failed write aborts the request, so a
change can never be applied without a record (`lib/admin/audit/record.ts`). The write also happens
**after** authentication and authorization, and both halves are load-bearing:

- Audit-first is why the entry precedes the change. Recording afterwards would leave a window where a
  mutation is applied and the record fails.
- Authorization-first is why the call sits inside the handler rather than in a route-level plugin. The
  admin handlers authorize in their own bodies (`assertAuth`, `assertSuperAdmin`, `assertGroupMember`,
  `assertGroupOwner` in `lib/admin/auth/rbac.ts:149-200`), so a plugin on `onBeforeHandle` would run
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

`lib/consts/admin_audit_routes.ts` enumerates every audited route with its action name and target
type, plus the deliberate exclusions. Each touches only the caller's own standing and nothing else,
which is the shared reason — the trail is a record of changes to managed entities, so an entry for
something that changed none of them is a row an investigator has to read past:

- `POST /admin/api/logout` — session lifecycle. Authentication-event logging would be its own feature.
- `PUT /admin/api/scope` — points the console at one of the teams the caller already belongs to (body
  `teamId`). It grants nothing, since a member can only switch to a team they are in and a super
  administrator reaches every project without switching, so there is no access event to record. The
  question an entry would have answered — which scope a change was made from — is already answered by the
  owning team on that change's own entry (stored `ownerGroupId`, shown `ownerTeamId`). See [[team-ownership]].
- `POST /admin/api/me/verification` (spec 078) — mails the caller a message proving their own address.
  Nothing changes until the mailbox holder completes it at the public verification endpoint, where there
  is no administrator to attribute. See [[admin-project-settings]].

The table also declares **non-route** audit actions (spec 078): `admin.register`, written with the
bootstrap actor when a person registers an administrator account at the public registration page. It
has no admin route, so it is declared beside the table rather than in it, and the drift guard keeps
comparing the table with mounted routes only.

It is not documentation:

- `recordAdminAudit` takes an `AuditAction` — the union of the table's `action` values — so an action
  the table does not declare cannot compile at the call site.
- `targetType` is resolved *from* the table, never passed by the caller, so it cannot be mistyped.
- `test/admin/audit_route_classification.spec.ts` compares the table against `elysia.routes` in both
  directions: a new mutating admin route with no entry fails and is named, and a row for a route the
  server does not serve fails too.

Same shape as [[feature-flag-gating]]'s route classification and the storage inventory, and for the
same reason: forgetting is the failure mode, so forgetting has to fail the suite. That sentence is
now the constitution's own argument for the whole class — this spec is the canonical worked example
of the completeness template in [[test-admission-rule]], because it enumerates `elysia.routes`, the
running server's actual surface, rather than the text of a source file, and it closes a claim about
absence that no example-based test can reach. The module imports
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
- `bucket.update` (shown as `project.update`) covers the whole update. It replaced `bucket.settings.update`,
  which fired only when a registration or verification field was present — so renaming a project or
  reassigning its managers left no trace. Historical entries keep the old name and stay filterable, because
  the action filter matches recorded values rather than a fixed enum.

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
route therefore allocates the id itself and passes it to the store: `userBucketStore.create` (and the
store of the old Project entity — a retired project — until spec 099 removed it) already accepted an
optional `_id`, and `UserStoreInstance.create`
and `createClient` gained one (`lib/admin/clients/routes.ts:96-101`). No per-operation exception to audit-first, at the cost of two signature
changes.

## Per-project targets need their project

End-user records carry `targetScope` — the project id (the stored bucket id) — because those users live in
per-project collections and `getUserStore(bucketId)` needs the project to resolve anyone. Without it an
`EndUser` entry names an opaque id that cannot be turned into an account, or even an email, without
searching every project. It is a separate field rather than a composite `targetId` so exact-match retrieval
on a bare user id keeps working. These routes are the only ones that set it — four end-user operations plus
`federation.identity.delete`, which severs one account's upstream link; see [[account-resolution]] for how
per-project user storage works.

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

`GET /admin/api/audit` is **team-scoped rather than super-admin only** — it was the latter until
ownership moved to teams ([[team-ownership]]). An administrator reads the trail of the teams they
belong to; a super administrator reads the instance, which is the only way entries belonging to no
team — settings, keys, administrator accounts — are readable at all. The restriction is computed from
the caller's own memberships and applied where entries are *selected*, never parsed from the query
string: it is the tenant boundary of this surface, so a caller-supplied team id would be a request to
read somebody else's trail. The owning team (stored `ownerGroupId`) is written at the time of the action and
never re-derived from `targetId`, so an entry outlives the project it describes.

**An entry about a project's people carries the project's team** (fixed 2026-10-13). The `enduser.*` entries the
console and MCP write were scoped only by `targetScope`, so the team-scoped read never selected them: a team's
administrators acted on their project's people and could not read that they had, in the Audit page or on a
person's Activity tab. They now carry the project's `ownerGroupId` (`scope`,
`lib/admin/users-end/routes.ts:202`), as the provisioning and group entries already did. Entries
written before stay as written, readable by a super administrator only, because the trail is never rewritten.

**An entry about a project's identity providers carries the project's team** (fixed 2026-10-15, after spec 100).
The `federation.provider.*` and `federation.identity.delete` entries named the project only as `targetId` or
`targetScope`, so a team configured its own project's sign-in providers and could not read that it had, while it
read every other change to the same project. They now carry `ownerGroupId` (`ownedBy`,
`lib/admin/federation/routes.ts:55`). As above, the entries written before stay super-administrator-only.

**A move belongs to two teams** (since spec 075). Moving a project (or, until spec 099, an old Project — now a
retired project) to another team writes one entry. Its `ownerGroupId` (shown `ownerTeamId`) is the team the
project joined, and `formerOwnerGroupId` (shown `formerOwnerTeamId`) is the team it left. The team-scoped read
selects on either field in all three backends, and each field has its own index
([[container-ownership-transfer]]). A second field rather than a second entry, because one action writes one
entry. The migration that made personal teams personal writes its removals under the
sentinel actor `system:migration` (`MIGRATION_ACTOR`), the bootstrap's convention: a `:` and no `@`. Since spec
090 the hourly pass that destroys a project whose 30 days ran out writes `bucket.purge` (shown `project.purge`)
as `system:retention` (`RETENTION_ACTOR`, `lib/consts/admin_audit_routes.ts:764`) through `recordSystemAudit`,
with `ownerGroupId` so the owning team reads it ([[project-soft-delete]]). Since then `bucket.delete` records the
scheduling, with `purgeAt`, and the destruction is the separate `bucket.purge`.

The read is newest-first, offset-paged, and filterable by actor (id
**or** email), action, target type, target id, scope and an inclusive time window. Since spec 085 there are
three more filters, all ANDed with the rest and with the team boundary, so they only narrow:
- `project=p` (named `bucket` until spec 100; the route hands it to the store's `bucket` filter,
  `lib/admin/audit/routes.ts:271`) matches entries whose target is the project (settings, address, owner, keys,
  providers), whose `targetScope` is it (end users, groups, provisioning, resources), or whose stored
  `bucketId` or `formerBucketId` is it. Since spec 099 client and resource entries carry the project as
  `bucketId` and its team as `ownerGroupId`, so a tenant reads its applications' and APIs' changes in its own
  trail — before, client entries carried no team and only a super administrator could read them.
  `formerBucketId` survives only on the bucket changes of retired projects, recorded before spec 099 removed
  them (`lib/adapters/types.ts:701-712`).
- `connection=c` matches the directory's own entries (`actor connection:c`) and entries targeting the
  connection.
- `actionPrefix` matches actions by prefix, escaped on every backend.

Since spec 087 an entry may carry `keys`, the kids a key act touched by role (`promoted`, `demoted`,
`generated`, `revoked`, `signing`), because a rotation or a revocation acts on up to three keys in one entry.
Key ids are public, as `kid` is.

Spec 088 added three actions and changed one entry:

- `provisioning.credential.retire` — an administrator ends a SCIM connection's overlapping previous secret or
  static token now. A previous value that ends by itself is not an act and writes nothing
  ([[scim-credential-overlap]]).
- `provisioning.credential.issue` now records in `to` the replaced value's latest end when it overlaps, or `null`
  when it stopped at once.
- `federation.provider.move` — one place up or down in a project's sign-in order; `from` and `to` are the order
  before and after, ids joined by `, `.
- `federation.provider.try` — the start of an administrator's try of a provider. It changes no managed entity, but it
  sends a browser to an upstream with the project's client credentials, and that is worth a record. Its result is not ([[federation-try-signin]]).

Also since spec 085:
- Key entries carry `kid`.
- `provisioning.connection.create` targets the new connection rather than its provider.
- Reads add `actorName` for directory and upstream actors (resolved per page, never stored).
- The console's Audit page keeps every filter in its address, pushes a change so Back restores the previous
  question, and shows applied filters as removable chips.

`bucket.address.change` entries (shown `project.address.change`) record the address before and after
(`from`/`to`, a slug or hostname, null for none). The route always passed them, but until 085 `write()` dropped
them and the entry schema had no such fields, so earlier address changes in the trail do not say where the
project was. Ordering is
`(timestamp desc, _id desc)`: `_id` is unique, so the order is total, which is what stops a page
boundary from dropping or repeating an entry when two actions land in the same millisecond. A backwards
window is refused with 422 rather than answered with an empty page — an empty page is
indistinguishable from "nothing happened", the one answer an audit trail must never give by accident.

## Read in today's words: translation on read and on filter (spec 100)

Spec 100 renamed the concepts at the edge — a bucket is a **project**, an administrator group a **team**, a
bucket group a **group** of end users — and left storage alone. The trail is the one place where stored names
reach the edge verbatim: its action ids, target types, attribute names and cascade keys. It is also evidence,
so it is **never rewritten**: no migration touches a stored entry, and new entries are still written under the
stored ids (`recordAdminAudit(ctx, 'bucket.create', …)`, with the `AuditAction` union in
`lib/consts/admin_audit_routes.ts` unchanged). The edge names exist only on the way out and on the way in,
in one import-free module, `lib/admin/vocabulary.ts`.

**Outbound.** `presentEntry` (`lib/admin/audit/routes.ts:106-133`) presents every listed entry through the
map:

- the action's **first segment** — `bucket.` → `project.` (so `bucket.key.rotate` reads `project.key.rotate`),
  `bucketgroup.` → `group.`, `group.` → `team.`, and the historic `project.` → `retiredproject.`
  (`ACTION_SEGMENTS`, `lib/admin/vocabulary.ts:18-23`); every other segment passes through;
- `targetType` — `UserBucket` → `Project`, `Group` → `Team`, `BucketGroup` → `Group`, `Project` →
  `RetiredProject` (`:25-30`);
- the fields `ownerGroupId`, `formerOwnerGroupId`, `bucketId`, `formerBucketId` → `ownerTeamId`,
  `formerOwnerTeamId`, `projectId`, `formerProjectId`;
- `attributes` names — `ownerGroupId` → `ownerTeamId`, `buckets.reservedHostnames` →
  `projects.reservedHostnames` (`:32-35`);
- the `cascade` key `projects` → `retiredProjects` (`:38-40`): it is only ever the count of old projects a
  bucket move carried before spec 099.

**Why retired projects.** Spec 099 removed the old Project entity, and its entries were stored as
`project.create`, `project.bucket.assign` and so on, with `targetType: 'Project'`. That is a different thing
from today's project. Had new entries simply been written as `project.*` from now on, the two would have merged
under one name in storage forever, and a filter for today's project actions would have returned the removed
entity's history. Mapping the first segment instead — a bijection — keeps the two apart: today's projects read
`project.*`, the removed entity reads `retiredproject.*`, and `group.*` (end users) never meets `team.*`
(administrators). Every edge id still matches `AUDIT_ACTION_PATTERN`
(`lib/consts/admin_audit_routes.ts:794`), `retiredproject.*` included.

**Inbound.** `storedFilters` (`lib/admin/audit/routes.ts:139-169`) maps the query back before it reaches the
store, so the adapters still see only stored names and none of them changed:

- `action` and `targetType` are inverse-mapped (`storedAction`, `storedTargetType`). A **stored-only name**
  such as `bucket.create` or `UserBucket` is not an edge name and names nothing: the route answers an empty
  page (`:254-257`) rather than reaching the entries the old name once meant. An unknown value passes through
  and matches nothing, as before.
- `actionPrefix` is inverse-mapped when it names whole segments (`project.`, `project.key.`, or a bare complete
  segment such as `team`). A prefix that stops **inside** a renamed first segment — `p`, `proj` — is refused 422
  (`storedActionPrefix`, `lib/admin/vocabulary.ts:78-87`): edge `p` would have to select both stored `bucket.`
  and `provisioning.`, which one stored prefix cannot express, and answering with half of it would be a wrong
  answer wearing a 200. A complete segment selects only itself: edge `project` reaches stored `bucket.` and
  never `bucketgroup.`.
- `project` replaces the `bucket` filter key (`lib/admin/audit/schema.ts:25`), handed to the store's `bucket`
  filter at `lib/admin/audit/routes.ts:271`. MCP's `audit_list` takes the same `project` argument.

**What does not change.** Visibility is still decided by the stored `ownerGroupId` / `formerOwnerGroupId`
against the caller's memberships (`:230-232`); a tenant administrator sees exactly the entries they saw before.
The console renders what the API returns, so its Audit page and a project's key history
(`actionPrefix=project.key.`, `lib/admin/ui/pages/BucketKeysPanel.tsx:34`) need no map of their own. The docs
export publishes the audited routes' actions and target types through the same functions
(`lib/docs_export/build.ts:27,171,180`), so the public reference shows edge names too.

## Related

- [[signing-keys]] — the key actions recorded here, and why deletion is not hot-applied
- [[deletion-and-revocation]] — a cascade is an effect of the already-recorded delete, and per-area counts stay out of the trail because a count is a value.
- [[admin-plane-error-shape]] — the other admin-plane contract a standalone mount cannot verify.
- [[feature-flag-gating]] — the declarative-table-plus-drift-guard pattern this reuses.
- [[account-resolution]] — per-project user storage, which is why `targetScope` exists.
- [[team-ownership]] — the team that owns a project, which is what the read is now scoped by, and
  why `ownerGroupId` is a separate field from `targetScope` rather than an overload of it.
- [[rich-authorization-requests]] — the other place a framework's schema handling behaved differently
  than reading it suggested.
- [[client-identity-from-database]] — client records are what several of these operations mutate.
- [[admin-console-signin]] — how the actor named in every entry is established, and the same
  authorization-before-write reasoning applied to an unauthenticated route.
- [[upstream-federation]] — the four rows it added, and why a provider's `targetType` is the project that
  holds it (stored `UserBucket`, shown `Project`) rather than the provider itself.
- [[project-is-the-only-container]] — the old Project entity whose entries now read as retired projects.

Verified against [[oauth-server-codebase]].
