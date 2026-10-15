---
type: concept
title: 'Moving a container to another group'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-15
---

# Moving a container to another group

A bucket moves from one administrator group to another with `PUT /admin/api/buckets/:id/owner`
(spec 075; `lib/admin/buckets/routes.ts:1122-1186`). Since spec 099 the bucket is the only
container ([[bucket-is-the-only-container]]), so this is the only move. Until then a project moved with its
bucket, and a project on the Default bucket moved alone through `PUT /admin/api/projects/:id/owner`; that
route and the project are gone. The bucket route is the only writer of a container's `ownerGroupId` after
creation. `ownerGroupId` still appears in no create or update body (`lib/admin/groups/schema.ts:3-7`).

The operation exists because a personal group stopped being shareable in the same change (see
[[group-ownership]]). Work started in someone's own workspace needs a way into a team's.

## Why what the bucket holds moves with it

Three things compare an application's bucket with the bucket it signs into:

- consent is waived only where they match (`consentWaived`, `lib/shared/consent_waiver.ts:33-44`);
- the bucket's group administers the end users that application signs in (`bucketCan`,
  `lib/admin/auth/can.ts:186-213`);
- since spec 092, the consent page calls a client "this organization's" only where they match, and
  "operator-registered" otherwise (`clientProvenance`, `lib/models/client/provenance.ts:68-79`). The waiver
  and the page share the comparison, `clientBelongsToBucket` (`provenance.ts:40-47`). See
  [[consent-screen-decisions]].

Until spec 099 those compared a project's group with the bucket's group, so a move had to carry every
project using the bucket in one change, or nobody would have decided the consequences. Now an application and
an API store the bucket's id, not a group, so they follow it **by reference**: the move writes the bucket
alone, and no state exists in which part of a bucket is in one group and part in another.

## Who may move what

- **Leaving a group** needs an owner of it: taking a container away removes every other member's access.
- **Joining a group** needs only membership: any member may already create containers there, so receiving
  one grants nothing new. The owner chose this rule (spec Q2).
- **Never a destination**: another administrator's personal group, Super administrators, and the group the
  container is already in. **Never moved**: the administrators' bucket and the Default bucket
  (`isUndeletableBucket`, checked before the bucket is loaded).

`loadDestination` (`lib/admin/ownership/destination.ts:27-44`) refuses in an order that reveals nothing.
Membership is checked before anything about the group's kind is said, so a caller outside the destination
gets the same answer as for an unknown id.

Since spec 079 the route decides the caller's right — the `move` flag the console and agents are shown —
before the destination: owning the bucket's group, or being a super administrator (`bucketCan`,
`can.ts:208-210`). A member without it gets 403, never a 409 describing the bucket.

## The source rule

`sourceGroupOf` (`destination.ts:64-74`) takes the bucket's owner, drops the destination, and requires a group
to remain: none left → 409 `already owned by this group`. Until spec 099 it took the owners of the bucket and
of every project using it, so a move could repair a half-done move or a project in a different group from its
bucket; with one owner there is nothing to repair. `assertGroupOwner(from)` then runs as before.

## One conditional write

The write goes through `ContainerOwnershipStore.moveBucket` (`lib/adapters/types.ts:2084-2093`), which sets
`ownerGroupId = to` only while the bucket is still in `from`, and answers `{status: 'conflict'}` otherwise.
It is a single conditional update on all three backends (for example
`lib/adapters/postgres/containerOwnershipStore.ts`), so of two racing moves only one finds the bucket in a
group it may leave; the route answers the other with 409. Business logic still gets no transaction from the
adapter contract, and now needs none.

Until spec 099 the move also rewrote every project using the bucket. On a standalone `mongod` that was
ordered conditional writes, bucket first, which left a half-done window declared as the
`container-move-atomicity` divergence, and a bind route that re-read the bucket after its write to undo a
binding raced by a move. Both are gone with the projects, and so is the divergence
(`lib/consts/storage_divergences.ts`). `database/verify_container_ownership.ts` checks the conditional write
against real databases.

## The trail sees both groups

A move writes one entry:

- `ownerGroupId` is the group the container joined;
- `formerOwnerGroupId` is the group it left (`types.ts:700`, `lib/admin/audit/record.ts:261-263`).

The group-scoped read matches either field in all three backends:

- memory: `admin_audit_query.ts:123`;
- MongoDB: `adminAuditStore.ts:88`;
- PostgreSQL: `adminAuditStore.ts:110`.

Each field has its own index (`storage_inventory.ts:781`).

A second field is used rather than a second entry, because one action writes one entry and audit-first
could not write two atomically. Entries written before a move keep the group that owned the container at
the time; they are never re-derived. The joining group sees the container's history from the move onward.

**`cascade` is no longer only a deletion's.** A bucket move counts what moved with it
(`{ applications, apis }` since spec 099, `{ projects }` before), and the personal-group migration counts the
members it removed. One entry still covers everything the action reached, as [[deletion-and-revocation]]
argues for deletions. The verb belongs to the action, though, so the console's column is **Also affected**
and derives the word from `action`: moved, removed or destroyed (`lib/admin/ui/pages/Audit.tsx:364-375`). It
was titled "Also destroyed", and a move read there as two destroyed projects — found while walking the
console through a move.

## The agent sees the preview

The route refuses without `confirm: true`, answering 409 with a preview: `from`, `to`, the bucket, and the
counts of `applications` and `apis` that move with it, plus the consequence in words. The MCP gate's
consequence report reads no entity state, so it cannot provide that itself. Until spec 075, `toOutcome`
reduced every 409 to `conflict: the operation was refused`, so an agent never saw a preview,
`bucket_address_change`'s included. It now passes a `confirmationRequired` body through whole as `preview`
(`lib/mcp/result.ts:79`). A confirmed move answers `{ bucket: { id, ownerGroupId } }`.

A confirmation token binds the arguments, and `confirm` is one of them. An agent therefore confirms the
preview and the move separately. `bucket_owner_change` is `high`.

## Making personal groups personal on upgrade

Migration `2026-10-09-personal-groups-single-member` (`lib/consts/migrations.ts:768`) removes every member
of a personal group except its first, and makes that one the owner. Before writing the group, it writes one
`group.member.remove` entry per group with:

- the deterministic id `<migration>:<group>`, so a rerun inserts nothing;
- actor `system:migration` (`lib/consts/admin_audit_routes.ts:758`);
- `cascade: { members: n }`.

The entry counts the removed members and names none. The trail records field names and counts, never
values, and the route's own removal entry does not name the removed user either. An operator who needs to
know who will lose access lists the shared personal groups before upgrading. The migration is not
reversible, and `db:migrate --plan` says so.

## Known residual race

A move into a group that is being deleted at the same moment can leave the container owned by a group that
no longer exists. Group deletion checks for emptiness, then destroys (`lib/admin/groups/routes.ts:284`, the
`DELETE /admin/api/groups/:id` handler). The same race already exists for creating a container into a group
being deleted. A super administrator can move the orphan out. It is recorded here rather than fixed.

## Related

- [[bucket-is-the-only-container]] — why projects were removed, and what a bucket holds instead.
- [[group-ownership]] — the ownership model this moves within, and why a personal group is no longer
  shareable.
- [[admin-audit-trail]] — the two-field group-scoped read.
- [[admin-mcp-control-plane]] — the `high` tool and the preview pass-through.
- [[postgresql-backend]] — the migration machinery and the divergence register.

Verified against [[oauth-server-codebase]].
