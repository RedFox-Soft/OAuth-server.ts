---
type: concept
title: 'Bucket groups: what roles became, the groups claim, and Super administrators'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-10-07
updated: 2026-10-07
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:scim-provisioning
    - predicate: depends_on
      object: concept:end-user-lifecycle
    - predicate: depends_on
      object: concept:group-ownership
---

# Bucket groups: what roles became, the groups claim, and Super administrators

Spec 071 — part 3 of 4 of the SCIM series (issue #62). There are no roles any more. **End users** are grouped
by **bucket groups**; **administrators** by administrator groups ([[group-ownership]]), one of which —
**Super administrators** — is the instance privilege that `super_admin` used to be. `project_admin` granted
nothing (it was assigned and never read) and is gone.

## Two kinds of group, on purpose

A bucket group (`BucketGroup`, `lib/adapters/types.ts:1312`) is a named set of one bucket's end users, kept by
administrators or owned by exactly one provisioning connection (`provisionedBy`, the same field and meaning as
on `User`). An administrator group owns projects and buckets and has owner/member standing and invitations.

They are not merged. They hold different people, have different shapes, and — the deciding reason — keeping the
privilege-granting set in a different entity from the one SCIM writes means no SCIM request and no token can
reach it **by construction**, not by a guard a later change could miss. The console and API say "bucket group"
(`bucket_group_*` tools) where the two could be confused; administrator groups keep `group_*`.

## Members are records, not a list on the group

Memberships live in their own area, one record per (group, user), id `groupId:userId`
(`lib/consts/storage_inventory.ts:554`). The first design put a member array on the group; it was dropped after
checking vendor behaviour: neither Okta nor Entra caps a group's size, "all employees" groups of 100,000+ are
real, and Entra fills a group with PATCH batches of ~40–200 members. Rewriting a member array on each batch is
quadratic write volume (the whole jsonb document on PostgreSQL, the whole field and its oplog entry on MongoDB)
and caps at ~370,000 members under MongoDB's 16 MB document limit. With records, a change costs what the change
is: on a standalone `mongod`, a 50-member change into a group growing to 10,000 measured ~10 ms throughout.

**Never read a group's members, edit the list in memory and write it back.** Every change is one
`BucketGroupStore.change(groupId, { attributes, add, remove })` (`lib/adapters/types.ts:1370`), made by the one
service function `applyGroupChange` (`lib/bucket_groups/service.ts:219`) for every surface — admin rename,
member routes, SCIM PUT and PATCH.

## All-or-nothing without multi-document transactions

RFC 7644 §3.5.2 makes a PATCH all or nothing. The service decides **every refusal before the first write** —
operations applied to a copy, every added id checked in one read (`assertMembersAllowed`, `:127`), a taken
name refused by the unique index before any membership is touched. Then the store writes: one transaction on
PostgreSQL and on a MongoDB replica set or sharded cluster (`supportsTransactions`,
`lib/adapters/mongodb/db.ts:31`); ordered, idempotent writes on a standalone `mongod`, where a database failure
mid-request can leave part of a change until the client's retry converges. That one failure mode is declared as
`bucket-group-change-atomicity` (`lib/consts/storage_divergences.ts:68`) beside its precedent
`migration-record-atomicity`, and listed in CONFORMANCE.md.

A SCIM PATCH also never reads the whole group: `membersTouchedBy` (`lib/scim/groups.ts:353`) reads which members
the operations name, and only a `replace` of `members` or a remove-all reads the full list. A group PATCH answers
204 — what Entra and Okta document — because a 200 would carry the whole member list on every batch.

## Ownership mirrors users

A connection's groups are read-only to administrators (409 naming the connection, as for a provisioned user;
IPSIE §4.2); a connection sees and changes only its own groups and may add only users it manages
(`assertActorMayChange`, `lib/bucket_groups/service.ts:84`). An administrator-kept group may hold provisioned
users — the membership belongs to the group, and the connection never sees it. A directory's create of a name an
administrator-kept group holds answers 409 `uniqueness`; an administrator may **hand the group over**
(`assignGroupToConnection`, `:310`), refused while any member is someone the connection does not manage, never
automatically. A connection that owns any group cannot be deleted.

## The groups claim

Built in, as `amr` is (`withGroupsScope`, `lib/consts/groups_claim.ts:32`): the `groups` scope releases the
`groups` claim whatever the claims setting holds, because a saved setting replaces the default whole and a
default entry would never reach those deployments. The value is the **display names**, sorted — readable and
checkable by a relying party; a rename changes it, which is acceptable because names are unique in the bucket and
only the owner renames. It is computed from membership after the account's stored claims are spread
(`lib/addon/account.ts:87`), so a stored `groups` can never forge it, and the admin claims route refuses one.

Where it appears: userinfo always; the ID token where scope claims go there today (`conformIdTokenClaims`); a
resource-bound access token and its introspection when the authorization granted `groups`
(`resourceTokenGroups`, `lib/bucket_groups/claim.ts:62` — a snapshot at issue, RFC 9068 §2.2.3.1). Above
`GROUPS_TOKEN_LIMIT` (200, Entra's JWT limit, `lib/consts/groups_claim.ts:21`) a token carries an OIDC Core
§5.6.2 distributed-claim reference to userinfo instead. **Known limit**: a resource server holding an
audience-bound token cannot call userinfo.

## Super administrators

`super-administrators`, kind `system` (`lib/admin/consts.ts`, seeded beside `unassigned`). The admin context's
`superAdmin` comes from the group-membership read every admin request already made (`lib/admin/auth/rbac.ts:250`)
— no extra query — and the group is removed from `memberships`, so it is never a working scope. It is invisible to
the group routes (404 to everyone, `lib/admin/groups/routes.ts:50`) and the scope switcher; a system group cannot
be renamed. Granting and withdrawing are operations of their own — `POST`/`DELETE /admin/api/admins/:id/super-admin`,
`high` on MCP — so creating or editing an account never grants it; the only writer is
`lib/admin/super_admins.ts` (`grantSuperAdmin`, `:45`). The last active member can be neither withdrawn nor
deactivated (`activeSuperAdminsWithout`, `:68`); first-run setup makes its administrator a member and stays closed
while the group has an active member.

Found while doing this: MCP's `project_create` and `bucket_create` were marked super-admin-only although their
routes had no such gate — an MCP-only refusal the console never applied. They are `superAdminOnly: false` now.

## The migration

`2026-10-08-roles-to-groups` (`lib/consts/migrations.ts:481`): every role a bucket declares or a user holds
becomes an administrator-kept group with exactly its holders — names differing only in case merge, blank ones are
skipped, all reported — and every holder of `super_admin`, active or not, joins Super administrators. The decisions
are pure (`planRoleMigration`, `:383`; `planSuperAdmins`, `:443`) and tested without a datastore; applying it twice
is checked against a real MongoDB by `database/verify_mongodb.ts`. `MigrationStep.apply` may now return report
lines, which `database/migrate.ts` prints.

## Related

- [[scim-provisioning]] — the connection, credentials and `/Users` this builds on.
- [[group-ownership]] — administrator groups, which own containers; Super administrators is one of them.
- [[end-user-lifecycle]] — deleting a user also removes their memberships.
