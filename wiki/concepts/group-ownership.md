---
type: concept
title: 'Group ownership of projects and buckets'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-29
updated: 2026-09-02
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:admin-console-signin
      source: oauth-server-codebase
      evidence: "The active scope is a property of the session established at sign-in — lib/admin/auth/rbac.ts:242: 'activeGroupId: await resolveActiveGroup(', re-resolved on every request rather than trusted from the cookie."
      confidence: high
      status: current
---

# Group ownership of projects and buckets

Every project and every user bucket is owned by exactly one **group**, and belonging to that group is
the only thing that grants access to it. There is no second ownership mechanism.

This replaced `managedBy: string[]` — a list of administrator ids on each container. That arrangement
could not express a tenant: a container was reachable by the people named on it, so it died with the
account that created it, and adding a second person meant a super administrator naming them on every
container individually. `POST /admin/api/projects` and `POST /admin/api/buckets` were also gated on
`super_admin`, so a project administrator could administer containers but never create one — while the
console offered the buttons anyway, producing a permission error for an action the interface invited.

## One mechanism, three kinds of group

`Group.kind` distinguishes three cases that differ only in their invariants, never in how access is
resolved (`lib/adapters/types.ts`):

- `personal` — created with an administrator's account. Undeletable, its administrator a permanent
  owner. It *may* gain further members, at which point it is an ordinary shared group. That is what
  makes sharing personal work an addition rather than a transfer, and it is why there is no second
  owner kind for "a user owns this". Sharing one is an API operation: the Groups table does not list
  personal groups, and the members editor is reached only for the groups it lists.
  Its stored `name` is its owner's email, and the console never shows that name to the owner —
  `groupLabel` (`lib/admin/ui/groupLabel.ts`) renders "Personal" for your own and
  "Personal — owner@email" for anyone else's. Two display sites labelling this differently is how a
  super administrator ended up reading a list of identical "Personal" rows.
- `regular` — a company or a team.
- `system` — the reserved `unassigned` holding group (`UNASSIGNED_GROUP_ID` in `lib/admin/consts.ts`),
  displayed as **System** (`SYSTEM_GROUP_NAME`, which `groupLabel` prefers over the stored name so a
  database seeded before the rename does not show the old one). No members, exempt from the
  at-least-one-owner rule, reachable only by super administrators.

`assertActiveGroup` (`lib/admin/auth/rbac.ts`) returns `unassigned` for a super administrator, who
belongs to no group by virtue of the role. That is deliberate and keeps one rule: it is exactly what
`managedBy: []` already meant, and it is the same rule the migration applies to an unmanaged container.

## Owner and member are properties of a membership, not roles

`GroupMember.role` is `owner` or `member`. An owner decides who is in the group and whether it may be
deleted; a member is equal to an owner over everything the group owns and has no say over membership.

This cannot live on the account beside `roles`. The same administrator is an owner of one group and a
plain member of another, so `assertGroupOwner` refuses by membership kind while `assertRole` refuses by
instance role — two independent dimensions, and conflating them is the mistake a third `group_owner`
instance role would have been.

## The hot path

`contextFor` resolves `getGroupStore().listByMember(user._id)` on **every** admin request, for both
credential types, exactly where it previously ran `listByManager` — so the per-request cost is
unchanged. Membership is embedded on the group (`members: GroupMember[]`) with a multikey index on
`members.userId`, because it is small, always read whole, and written only by membership operations.

Re-reading per request rather than caching at sign-in is what makes a removed member lose access on
their *next* call rather than at their next sign-in.

## The active scope

`AdminSession.activeGroupId` is the group the console is pointed at: what is listed, and where a new
container is created. Server-held rather than caller-asserted, because it sits on an authorization
boundary — a client-supplied scope could name a group the caller has since been removed from. It is
re-validated against live membership on every request and falls back to the personal group, so a
removed member keeps a usable console instead of being stranded in a scope they cannot navigate out of.

A super administrator is the one exception to that re-validation, and it cuts both ways. They may
switch into any group they do not belong to — instance-wide authority has to be able to create into a
scope, and support a group whose owners have gone — so `resolveActiveGroup` honours their choice after
re-reading the group, rather than discarding it and silently sending their next creation to
`unassigned`. What they may *not* switch into is another administrator's `personal` group: it is one
person's own workspace, not a tenant needing support. Both routes in `lib/admin/scope/routes.ts` apply
that carve-out — the list never offers what the switch would refuse — and all three of the switch's
refusals share one message, so it cannot be used to learn which group ids exist or which are personal.

Switching writes **no audit entry**. `PUT /admin/api/scope` is one of the two routes
`excludedAdminRoutes` names, alongside logout, and for the same reason: the session is the only thing it
changes. It also grants nothing — a member can only switch to a group they are already in, and a super
administrator reaches every container without switching — so there is no access event to record. Which
scope a change was made from is answered by `ownerGroupId` on that change's own entry rather than by a
separate row, which is the better record anyway: a switch entry names only the group switched *to*.
See [[admin-audit-trail]].

An agent has no session, so there is nothing for it to switch. `PUT /admin/api/scope` is therefore not
published as a tool at all — it is named in `excludedConsoleOperations` as `inapplicable`, the same
category as logout and first-run setup, so an agent is not offered an operation it has no principal
for. The create tools instead take an explicit `groupId` validated against the acting administrator's
memberships — the one place the agent surface's request shape differs from the console's, and it
differs in the safe direction.

## Gotchas

**A refusal must not reveal existence.** `loadProject`, `loadGroup` and the bucket loaders answer the
same status for a container that does not exist as for one owned by another group, for any caller
without instance-wide authority. They did not before this feature: 404 versus 403 was an oracle for
enumerating ids, harmless while ids came only from an operator and not harmless once every id belongs
to somebody else's tenant. A super administrator still gets 404, because there is no tenant they could
be probing. Caught by `test/admin/group_isolation.spec.ts`, which exists to ask the opposite question
from every other spec: not "can this administrator do what they should" but "is anything at all of
another tenant observable".

**A project and its bucket must share a group.** Enforced on `PUT /admin/api/projects/:id/bucket`, and
it is a coherence rule about the data rather than a statement about authority — so a super
administrator is refused too. Joining them across groups would leave a project's end-users administered
by a group with no access to the project.

**Listing has to agree with access.** `assertBucketUserAccess` admits a bucket backing a project the
caller's group owns, so `GET /admin/api/buckets` has to admit it as well. It did not before this
feature, and a bucket you could administer but never see was the result.

**The audit trail's group is written, never derived.** `AdminAuditEntry.ownerGroupId` is a separate
field from `targetScope`, which already means "the bucket within which `targetId` resolves". It is
recorded at the time of the action and never re-derived from `targetId`, so an entry outlives the
container it describes. The read restriction is computed from the caller's own memberships in the
handler and never parsed from the query string — see [[admin-audit-trail]] for why a filter that is
silently dropped is the specific hazard on this surface.

**Two seeds, one change.** `ensureAdminSeed` (`lib/admin/seed.ts`) is test-only; `database/mongodb.ts`
is the real deployment seed. Both create the bootstrap administrator, so both must create its personal
group and the reserved `unassigned` group. Changing only one silently no-ops in production. The
holding group's *name* is the exception to "idempotent means insert-only": the deployment seed `$set`s
it from `SYSTEM_GROUP_NAME` on every run, because a label carrying no behaviour should be corrected in
a database that already has the document rather than only in fresh ones.

## The migration

`planOwnershipMigration` (`lib/admin/groups/migration.ts`) is a pure function so the rule is testable
without a database. Three rules: one manager → that administrator's personal group; two or more →
a generated group whose membership is *exactly* that set; none → `unassigned`.

The middle rule must not be simplified. Grouping by "first manager" or "any shared manager" would merge
`{A,B}` and `{A,C}` into one group, handing B access to C's containers — a cross-tenant leak created by
the migration itself, and invisible afterwards because the result looks like an ordinary group. The
rule can *split* one conceptual tenant into two, which is the safe direction: a super administrator can
merge them, whereas an incorrect merge has already leaked. Generated groups carry `needsReview` so the
console asks somebody to confirm the grouping.

## Related

- [[admin-audit-trail]] — the trail this feature made group-scoped, and the load-bearing route table
  every new group route had to be added to.
- [[admin-mcp-control-plane]] — why `group_delete` is withheld from agents rather than
  confirmation-gated: it destroys a container with nothing left afterwards to inspect, the same class
  as the two container deletions already withheld.
- [[admin-console-signin]] — how the session that now carries the active scope is established.
- [[account-resolution]] — per-bucket end-user storage, which is why bucket access has a broad form and
  a strict one.

Verified against [[oauth-server-codebase]] as changed by `specs/033-project-admin-self-service`.
