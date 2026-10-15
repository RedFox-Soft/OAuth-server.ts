---
type: concept
title: 'Moving a project to another team'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-15
---

# Moving a project to another team

A project moves from one team to another with `PUT /admin/api/projects/:id/owner` (spec 075;
`lib/admin/buckets/routes.ts:1128-1192`), whose body names the destination as `teamId`; the MCP tool is
`project_owner_change`, taking `teamId` too. A project is stored as a bucket (`UserBucket`) and a team as an
administrator group (`Group`), so the stored owner field is still `ownerGroupId`; spec 100 renamed only the
edge (`/admin/api/buckets/:id/owner`, `groupId` and `bucket_owner_change` until then). Since spec 099 the
project is the only container ([[project-is-the-only-container]]), so this is the only move. Until then the
old Project entity (a retired project) moved with its bucket, and one on the Default bucket moved alone
through its own owner route, which was then at the `/admin/api/projects/:id/owner` path the project route
holds now; that route and that entity are gone. The project route is the only writer of a container's
`ownerGroupId` after creation. `ownerGroupId` still appears in no create or update body
(`lib/admin/groups/schema.ts:3-7`).

The operation exists because a personal team stopped being shareable in the same change (see
[[team-ownership]]). Work started in someone's own workspace needs a way into a shared team's.

## Why what the project holds moves with it

Three things compare an application's project with the project it signs into:

- consent is waived only where they match (`consentWaived`, `lib/shared/consent_waiver.ts:33-44`);
- the project's team administers the end users that application signs in (`bucketCan`,
  `lib/admin/auth/can.ts:186-213`);
- since spec 092, the consent page calls a client "this organization's" only where they match, and
  "operator-registered" otherwise (`clientProvenance`, `lib/models/client/provenance.ts:68-79`). The waiver
  and the page share the comparison, `clientBelongsToBucket` (`provenance.ts:40-47`). See
  [[consent-screen-decisions]].

Until spec 099 those compared a retired project's team with the bucket's team, so a move had to carry every
retired project using the bucket in one change, or nobody would have decided the consequences. Now an
application and an API store the project's id (`bucketId`), not a team, so they follow it **by reference**:
the move writes the project alone, and no state exists in which part of a project is in one team and part in
another.

## Who may move what

- **Leaving a team** needs an owner of it: taking a container away removes every other member's access.
- **Joining a team** needs only membership: any member may already create containers there, so receiving
  one grants nothing new. The owner chose this rule (spec Q2).
- **Never a destination**: another administrator's personal team, Super administrators, and the team the
  container is already in. **Never moved**: the administrators' project and the Default project
  (`isUndeletableBucket`, checked before the project is loaded).

`loadDestination` (`lib/admin/ownership/destination.ts:27-44`) refuses in an order that reveals nothing.
Membership is checked before anything about the team's kind is said, so a caller outside the destination
gets the same answer as for an unknown id.

Since spec 079 the route decides the caller's right — the `move` flag the console and agents are shown —
before the destination: owning the project's team, or being a super administrator (`bucketCan`,
`can.ts:208-210`). A member without it gets 403, never a 409 describing the project.

## The source rule

`sourceGroupOf` (`destination.ts:64-74`) takes the project's owner, drops the destination, and requires a team
to remain: none left → 409 `already owned by this team` (`group` until spec 100). Until spec 099 it took the owners of the bucket and of every retired project
using it, so a move could repair a half-done move or a retired project in a different team from its bucket;
with one owner there is nothing to repair. `assertGroupOwner(from)` then runs as before.

## One conditional write

The write goes through `ContainerOwnershipStore.moveBucket` (`lib/adapters/types.ts:2084-2093`), which sets
`ownerGroupId = to` only while the project is still in `from`, and answers `{status: 'conflict'}` otherwise.
It is a single conditional update on all three backends (for example
`lib/adapters/postgres/containerOwnershipStore.ts`), so of two racing moves only one finds the project in a
team it may leave; the route answers the other with 409. Business logic still gets no transaction from the
adapter contract, and now needs none.

Until spec 099 the move also rewrote every retired project using the bucket. On a standalone `mongod` that
was ordered conditional writes, bucket first, which left a half-done window declared as the
`container-move-atomicity` divergence, and a bind route that re-read the bucket after its write to undo a
binding raced by a move. Both are gone with the old Project entity, and so is the divergence
(`lib/consts/storage_divergences.ts`). `database/verify_container_ownership.ts` checks the conditional write
against real databases.

## The trail sees both teams

A move writes one entry. Stored, it carries:

- `ownerGroupId`, the team the container joined;
- `formerOwnerGroupId`, the team it left (`types.ts:700`, `lib/admin/audit/record.ts:261-263`).

The console and `audit_list` present them as `ownerTeamId` and `formerOwnerTeamId` (translated on read by
`presentEntry`, `lib/admin/audit/routes.ts:106-133`; the stored entry is never rewritten). The team-scoped read matches either field
in all three backends:

- memory: `admin_audit_query.ts:123`;
- MongoDB: `adminAuditStore.ts:88`;
- PostgreSQL: `adminAuditStore.ts:110`.

Each field has its own index (`storage_inventory.ts:781`).

A second field is used rather than a second entry, because one action writes one entry and audit-first
could not write two atomically. Entries written before a move keep the team that owned the container at
the time; they are never re-derived. The joining team sees the container's history from the move onward.

**`cascade` is no longer only a deletion's.** A project move counts what moved with it
(`{ applications, apis }` since spec 099; before, the retired projects it carried, stored as `{ projects }`
and presented since spec 100 as `{ retiredProjects }`), and the personal-team migration counts the
members it removed. One entry still covers everything the action reached, as [[deletion-and-revocation]]
argues for deletions. The verb belongs to the action, though, so the console's column is **Also affected**
and derives the word from `action`: moved, removed or destroyed (`lib/admin/ui/pages/Audit.tsx:364-375`). It
was titled "Also destroyed", and a move read there as two destroyed (retired) projects — found while walking
the console through a move.

## The agent sees the preview

The route refuses without `confirm: true`, answering 409 with a preview: `from`, `to` (the two teams), the
`project`, and the counts of `applications` and `apis` that move with it, plus the consequence in words. The
MCP gate's consequence report reads no entity state, so it cannot provide that itself. Until spec 075,
`toOutcome` reduced every 409 to `conflict: the operation was refused`, so an agent never saw a preview,
`project_address_change`'s (then `bucket_address_change`) included. It now passes a `confirmationRequired`
body through whole as `preview` (`lib/mcp/result.ts:79`). A confirmed move answers
`{ project: { id, ownerTeamId } }` (`lib/admin/buckets/routes.ts:1190`).

A confirmation token binds the arguments, and `confirm` is one of them. An agent therefore confirms the
preview and the move separately. `project_owner_change` is `high`.

## Making personal teams personal on upgrade

Migration `2026-10-09-personal-groups-single-member` (`lib/consts/migrations.ts:768`) removes every member
of a personal team except its first, and makes that one the owner. Before writing the team, it writes one
`group.member.remove` entry per team (the stored id; the trail presents it as `team.member.remove`) with:

- the deterministic id `<migration>:<group>`, so a rerun inserts nothing;
- actor `system:migration` (`lib/consts/admin_audit_routes.ts:758`);
- `cascade: { members: n }`.

The entry counts the removed members and names none. The trail records field names and counts, never
values, and the route's own removal entry does not name the removed user either. An operator who needs to
know who will lose access lists the shared personal teams before upgrading. The migration is not
reversible, and `db:migrate --plan` says so.

## Known residual race

A move into a team that is being deleted at the same moment can leave the container owned by a team that
no longer exists. Team deletion checks for emptiness, then destroys (`lib/admin/groups/routes.ts:302`, the
`DELETE /admin/api/teams/:id` handler). The same race already exists for creating a container into a team
being deleted. A super administrator can move the orphan out. It is recorded here rather than fixed.

## Related

- [[project-is-the-only-container]] — why the old Project entity was removed, and what a project holds instead.
- [[team-ownership]] — the ownership model this moves within, and why a personal team is no longer
  shareable.
- [[admin-audit-trail]] — the two-field team-scoped read.
- [[admin-mcp-control-plane]] — the `high` tool and the preview pass-through.
- [[postgresql-backend]] — the migration machinery and the divergence register.

Verified against [[oauth-server-codebase]].
