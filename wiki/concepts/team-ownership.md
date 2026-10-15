---
type: concept
title: 'Team ownership of projects'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-29
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:admin-console-signin
      source: oauth-server-codebase
      evidence: "The active scope is a property of the session established at sign-in — lib/admin/auth/rbac.ts:253: 'activeGroupId: await resolveActiveGroup(', re-resolved on every request rather than trusted from the cookie."
      confidence: high
      status: current
---

# Team ownership of projects

Every project is owned by exactly one **team**, and belonging to that team is the only thing that
grants access to it — and to the applications and APIs it holds. There is no second ownership mechanism.
Until spec 099 the old Project entity (a retired project) was owned the same way and gave its team reach
over the bucket it named; that entity is gone, and the project is the only container
([[project-is-the-only-container]]).

A project is stored as a bucket (`UserBucket`, area `userBuckets`) and a team as an administrator group
(`Group`, area `groups`); the code keeps those names, which is why the identifiers below say `Group`,
`ownerGroupId` and `activeGroupId`. Spec 100 renamed only the edge: the admin API is `/admin/api/teams…` and
`/admin/api/projects…`, its fields are `ownerTeamId`, `teamId` and `activeTeamId`, and the MCP tools are
`team_*` and `project_*`. The word "group" now means only a project's set of end users
([[project-groups]]).

This replaced `managedBy: string[]` — a list of administrator ids on each container. That arrangement
could not express a tenant: a container was reachable by the people named on it, so it died with the
account that created it, and adding a second person meant a super administrator naming them on every
container individually. Creating either container (the retired project and the bucket, as they were
then) was also gated on `super_admin`, so a tenant administrator could administer containers but never
create one — while the console offered the buttons anyway, producing a permission error for an action the
interface invited.

## One mechanism, three kinds of team

`Group.kind` distinguishes three cases that differ only in their invariants, never in how access is
resolved (`lib/adapters/types.ts`):

- `personal` — the personal team, created with an administrator's account. Undeletable, and its
  administrator is its **one member** (since spec 075). Until then it could gain members and become an
  ordinary shared team, meant to make sharing personal work an addition rather than a transfer. That
  ambiguity is what let a colleague's default scope land in someone else's personal team (see The active
  scope below). Now adding a member and inviting someone are both refused (`assertShareable`,
  `lib/admin/groups/routes.ts:86`), and so is accepting an invitation issued earlier
  (`lib/admin/groups/accept.ts:89`). Sharing *is* a transfer now: the project moves into a
  shared team ([[container-ownership-transfer]]). The upgrade removed every member but the first
  from existing personal teams, one audit entry per team. The Teams table still does not list
  personal teams.
  Its stored `name` is its owner's email, and the console never shows that name to the owner —
  `groupLabel` (`lib/admin/groups/label.ts`) renders "Personal" for your own and
  "Personal — owner@email" for anyone else's. Two display sites labelling this differently is how a
  super administrator ended up reading a list of identical "Personal" rows. It moved out of
  `lib/admin/ui/` in spec 077 because the server labels with it too: the usage overview names every
  project's customer for the console and the agent alike, always in the third-party form
  ([[monthly-active-users]]).
- `regular` — a shared team: a company or a department.
- `system` — two reserved teams. The `unassigned` holding team (`UNASSIGNED_GROUP_ID` in
  `lib/admin/consts.ts`), displayed as **System** (`SYSTEM_GROUP_NAME`, which `groupLabel` prefers over the
  stored name so a database seeded before the rename does not show the old one): no members, exempt from the
  at-least-one-owner rule, reachable only by super administrators. And **Super administrators**
  (`SUPER_ADMINS_GROUP_ID`, since spec 071): its membership *is* the instance privilege `super_admin` used to
  be; it owns nothing, is never a working scope, and is invisible to the team routes ([[project-groups]]). A
  system team cannot be renamed.

`assertActiveGroup` (`lib/admin/auth/rbac.ts`) returns `unassigned` for a super administrator, who
belongs to no working team by virtue of the privilege (Super administrators is not among `memberships`). That is deliberate and keeps one rule: it is exactly what
`managedBy: []` already meant, and it is the same rule the migration applies to an unmanaged container.

## Owner and member are properties of a membership, not roles

`GroupMember.role` is `owner` or `member`. An owner decides who is in the team and whether it may be
deleted; a member is equal to an owner over everything the team owns and has no say over membership.
Two exceptions since spec 081 ([[project-workspace]]): deleting a project that still holds accounts is an
owner's act, and a team owner (not a member) may change an unused project's path. Since spec 090 the same
right decides restoring such a project and deleting it now ([[project-soft-delete]]).

This cannot live on the account. The same administrator is an owner of one team and a plain member of
another, so `assertGroupOwner` refuses by membership kind while `assertSuperAdmin` refuses by membership of
Super administrators — two independent dimensions, and conflating them is the mistake a `team_owner`
privilege would have been. (Accounts carry no roles at all since spec 071; [[project-groups]].)

**The team page (spec 085).** `/admin/teams/:id` (`lib/admin/ui/pages/groups/AdminGroupPage.tsx`) is run by
the team's owners, not only by super administrators.
- `GET /admin/api/teams/:id` gives every member their colleagues' emails and `active` flags. Before, the
  console took names from the super-administrator-only administrator list, so an owner saw raw ids.
- The read also gives `owns` (`owns.projects`; retired projects too until spec 099) and `can`:
  `manageMembers`, `invite` and `delete` for owners of a shared team; `addExisting` for super
  administrators; `rename` everywhere but System.
- List rows carry `owns` counts.
- Any owner invites by email; the form states what the invitee will reach.
- Removing a member states "They lose access to N projects" (`AdminGroupPage.tsx:225`). Leaving has its own text.
- The last owner's role change and removal are shown unavailable before the server's 409.
- A refused deletion answers 409 `team still owns projects` with blockers `[{kind: 'project', count}]`
  (`lib/admin/groups/routes.ts:314-315`); until 085 they were mislabelled `client` and `enduser`, until
  099 a kind for the retired project stood beside the bucket's, and until spec 100 the message read
  `group still owns buckets` with kind `'bucket'`.

## The hot path

`contextFor` resolves `getGroupStore().listByMember(user._id)` on **every** admin request, for both
credential types, exactly where it previously ran `listByManager` — so the per-request cost is
unchanged. Membership is embedded on the team record (`members: GroupMember[]`) with a multikey index on
`members.userId`, because it is small, always read whole, and written only by membership operations.

Re-reading per request rather than caching at sign-in is what makes a removed member lose access on
their *next* call rather than at their next sign-in.

## The active scope

**"Their personal team" means the one they own, not one they belong to** (corrected 2026-09-29;
since spec 075 nobody can belong to another's personal team, so the two readings no longer differ, but
the owner predicate stays — it is the correct one).
`findPersonalFor` matched any personal team the administrator was a member of, and so did
`resolveActiveGroup`'s fallback; once someone added a colleague to their own personal team, both could
answer with that team — stores return in insertion order, so the older account's won. It was the
colleague's default scope at every sign-in, and whatever they then created landed in the other
person's team. The owner is the first member (every membership write appends, maps or filters, so
`members[0]` never moves), and all three backends and the fallback now match on it
(`lib/admin/auth/rbac.ts:304`). `own` in `GET /admin/api/scope` always did. Since spec 075 the attack
cannot be set up at all — nobody joins another's personal team — so `assertPersonalOwnerKept` and
`test/admin/personal_group_ownership.spec.ts` were removed with it; `test/admin/personal_group_sharing.spec.ts`
proves the door is shut.

`AdminSession.activeGroupId` is the team the console is pointed at: what is listed, and where a new
container is created. The edge shows it as `activeTeamId` (`/admin/api/me` and the console shell, built by
`meView`, `lib/admin/me_view.ts:26`). Server-held rather than caller-asserted, because it sits on an
authorization boundary — a client-supplied scope could name a team the caller has since been removed from.
It is re-validated against live membership on every request and falls back to the personal team, so a
removed member keeps a usable console instead of being stranded in a scope they cannot navigate out of.

A super administrator is the one exception to that re-validation, and it cuts both ways. They may
switch into any team they do not belong to — instance-wide authority has to be able to create into a
scope, and support a team whose owners have gone — so `resolveActiveGroup` honours their choice after
re-reading the team, rather than discarding it and silently sending their next creation to
`unassigned`. What they may *not* switch into is another administrator's `personal` team: it is one
person's own workspace, not a tenant needing support. Both routes in `lib/admin/scope/routes.ts` apply
that carve-out — the list never offers what the switch would refuse — and all three of the switch's
refusals share one message, so it cannot be used to learn which team ids exist or which are personal.

Switching writes **no audit entry**. `PUT /admin/api/scope` is one of the two routes
`excludedAdminRoutes` names, alongside logout, and for the same reason: the session is the only thing it
changes. It also grants nothing — a member can only switch to a team they are already in, and a super
administrator reaches every container without switching — so there is no access event to record. Which
scope a change was made from is answered by the owning team on that change's own entry (stored
`ownerGroupId`, presented as `ownerTeamId`) rather than by a separate row, which is the better record
anyway: a switch entry names only the team switched *to*. See [[admin-audit-trail]].

An agent has no session, so there is nothing for it to switch. `PUT /admin/api/scope` is therefore not
published as a tool at all — it is named in `excludedConsoleOperations` as `inapplicable`, the same
category as logout and first-run setup, so an agent is not offered an operation it has no principal
for. Since spec 087 project creation takes an optional `teamId` (`groupId` until spec 100; `project_create`
takes it too) and checks it with the move's `loadDestination` (`lib/admin/buckets/routes.ts:774-777`): the
caller must be a member, and Super administrators and another administrator's personal team are never a
destination. Without it, the active team decides, as before. An application or API is created inside a
project, so it needs no team of its own: it is the project's team's (spec 099, which removed creating the
old Project entity and its team argument with it). The console's creation dialog chooses the team, so the
header switcher is a default rather than the only way to say where something goes.

## Gotchas

**A refusal must not reveal existence.** `loadGroup` and the project loaders answer the
same status for a container that does not exist as for one owned by another team, for any caller
without instance-wide authority. They did not before this feature: 404 versus 403 was an oracle for
enumerating ids, harmless while ids came only from an operator and not harmless once every id belongs
to somebody else's tenant. A super administrator still gets 404, because there is no tenant they could
be probing. Caught by `test/admin/group_isolation.spec.ts`, which exists to ask the opposite question
from every other spec: not "can this administrator do what they should" but "is anything at all of
another tenant observable".

**Skipping consent is a decision about your own users only** (added 2026-09-29). A client's
`consent.require: false` is honoured only when the project it signs into is the project it belongs to
(`consentWaived`, `lib/shared/consent_waiver.ts:33-44`), decided per request. Until spec 099 the test was
"the team owning its (retired) project owns the bucket", and an old Project on the Default bucket signed
into a population every tenant shares — so honouring the flag there gave a tenant every Default-project
user's claims with `prompt=none` and no page. Since 099 a tenant cannot have an application in the Default
project at all, and the upgrade turned consent back on for those that came from tenant retired projects
there. A client that belongs to no project keeps the flag as stored, since only the operator can have set it
(registration and client documents cannot); the console's own client passes because it belongs to the
administrators' project (`lib/consts/admin_seed.ts:100`). `consentWaived` is the only
reader of the flag that makes a grant `trusted` (via `loadExistingGrant`, `lib/addon/account.ts`): until
2026-10-09 the `Grant` constructor also derived `trusted` from `consent.require` when handed a client,
skipping the project check — unreachable only because no caller passed one. It now defaults to `false`. The
spec is `test/consent_waiver/`.

Since spec 092 the comparison itself is one function — `projectGroupOwnsBucket` until spec 099,
`clientBelongsToBucket` since (`lib/models/client/provenance.ts:40-47`). The waiver calls it
(`lib/shared/consent_waiver.ts:43`), and so does `clientProvenance`, which words the consent page: a client
of the sign-in project is "this organization's", one of another project is "operator-registered". The two
callers read a client of no project differently, on purpose. The waiver keeps the stored flag, which a
self-registered client cannot carry. The page tests self-registration first, so by the time it asks, "no
project" can only mean the operator's own. `consentWaived` is still the only reader of `consent.require`. See [[consent-screen-decisions]].

**An application and its project cannot be in different teams.** Until spec 099 the old Project entity (a
retired project) recorded a team that had to equal its bucket's, enforced on the bind route and re-checked
after the write, because a move could commit in between. Since 099 an application and an API carry no team
at all, only `bucketId`, so there is nothing to disagree and a project's move carries them by reference
([[container-ownership-transfer]]).

**Listing has to agree with access.** A project's `read` right (`bucketCan`, `lib/admin/auth/can.ts`,
which replaced `assertBucketUserAccess` in spec 079) is membership of its team, so `GET /admin/api/projects`
lists the active team's projects (`lib/admin/buckets/visible.ts`). Until spec 099 the right also admitted a
bucket backing a retired project the caller's team owned, and the list had to add those; before this
feature it did not, and a container you could administer but never see was the result.

**The audit trail's team is written, never derived.** `AdminAuditEntry.ownerGroupId` (presented as
`ownerTeamId`) is a separate field from `targetScope`, which already means "the project within which
`targetId` resolves". It is recorded at the time of the action and never re-derived from `targetId`, so an
entry outlives the container it describes. The read restriction is computed from the caller's own
memberships in the handler and never parsed from the query string — see [[admin-audit-trail]] for why a
filter that is silently dropped is the specific hazard on this surface.

**Two seeds, one change.** `ensureAdminSeed` (`lib/admin/seed.ts`) is test-only; `database/mongodb.ts`
is the real deployment seed. Both create the bootstrap administrator, so both must create its personal
team and the reserved `unassigned` team. Changing only one silently no-ops in production. The
holding team's *name* is the exception to "idempotent means insert-only": the deployment seed `$set`s
it from `SYSTEM_GROUP_NAME` on every run, because a label carrying no behaviour should be corrected in
a database that already has the document rather than only in fresh ones.

## The migration

**Retired at `92a60cd`**: `lib/admin/groups/migration.ts` no longer exists, and the conversion was not
carried into the schema-migration layer (see [[postgresql-backend]]). A deployment old enough to still
hold `managedBy` upgrades through an earlier release first. The rule it applied is kept below because
it is the argument against the obvious simplification, should anyone ever regroup containers again.

`planOwnershipMigration` was a pure function so the rule was testable
without a database. Three rules: one manager → that administrator's personal team; two or more →
a generated team whose membership is *exactly* that set; none → `unassigned`.

The middle rule must not be simplified. Grouping by "first manager" or "any shared manager" would merge
`{A,B}` and `{A,C}` into one team, handing B access to C's containers — a cross-tenant leak created by
the migration itself, and invisible afterwards because the result looks like an ordinary team. The
rule can *split* one conceptual tenant into two, which is the safe direction: a super administrator can
merge them, whereas an incorrect merge has already leaked. Generated teams carry `needsReview` so the
console asks somebody to confirm the grouping.

## Related

- [[container-ownership-transfer]] — moving a project, with what it holds, to another team; how sharing
  personal work is done since personal teams stopped being shareable.
- [[project-is-the-only-container]] — why the old Project entity went, and what replaced each thing it did.
- [[admin-provisioning]] — the scripts that seed the `unassigned` team and the reserved containers
- [[admin-audit-trail]] — the trail this feature made team-scoped, and the load-bearing route table
  every new team route had to be added to.
- [[admin-mcp-control-plane]] — why `team_delete` is withheld from agents rather than
  confirmation-gated: it destroys a container with nothing left afterwards to inspect, the same class
  as the two container deletions already withheld.
- [[admin-console-signin]] — how the session that now carries the active scope is established.
- [[plans]] — the per-administrator limits count the teams in which an administrator holds the owner role (spec 102).
- [[account-resolution]] — per-project end-user storage, which is why project access had a broad form and
  a strict one. Since spec 099 the two loaders (`loadBucketForUsers`, `loadBucketForEdit`,
  `lib/admin/buckets/access.ts:49-118`) admit the same callers — membership of the project's team — because
  the broad form's extra reach came through the old Project entity.

Verified against [[oauth-server-codebase]].
