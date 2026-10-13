---
type: concept
title: 'Moving a container to another group'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-13
---

# Moving a container to another group

A bucket and the projects that use it move from one administrator group to another as **one change**
(specs/075): `PUT /admin/api/buckets/:id/owner` (`lib/admin/buckets/routes.ts:561`). A project with no
bucket of its own moves alone: `PUT /admin/api/projects/:id/owner` (`lib/admin/projects/routes.ts:417`).
These two routes are the only writers of a container's `ownerGroupId` after creation. `ownerGroupId` still
appears in no create or update body (`lib/admin/groups/schema.ts:3-7`).

The operation exists because a personal group stopped being shareable in the same change (see
[[group-ownership]]). Work started in someone's own workspace needs a way into a team's.

## Why the bucket and its projects move together

Three things compare a project's owner with the owner of the bucket it signs into:

- consent is waived only where they match (`consentWaived`, `lib/shared/consent_waiver.ts:33-45`);
- a project's group may administer the end users of its bucket (the bucket's `manageUsers` right,
  `bucketCan` in `lib/admin/auth/can.ts` since spec 079);
- since spec 092, the consent page calls a client "this organization's" only where they match, and
  "operator-registered" otherwise (`clientProvenance`, `lib/models/client/provenance.ts:68-78`). The waiver
  and the page share the comparison, `projectGroupOwnsBucket` (`provenance.ts:38-45`). See
  [[consent-screen-decisions]].

Moving one without the other would change all three, and nobody would have decided that. This is the same reason
`PUT /admin/api/projects/:id/bucket` refuses to bind a project to another group's bucket.

## Changing a project's bucket is previewed (spec 085)

Pointing a project at another bucket, or back to Default (`DELETE …/bucket`), gives every application of the
project a new issuer. Everyone signed in through them must sign in again, because the account lookup follows
the project's current bucket while their refresh tokens name the old one. Both routes are preview-then-confirm
(`lib/admin/projects/routes.ts`):

- The rights and state refusals above come first.
- Without `confirm`, the route answers 409 naming the applications, `from`/`to` (bucket, name and issuer), the
  declarations that move (`previewMove`, `lib/admin/resources/move.ts`), `conflicts`, `rootRefused`, and
  `expect: {applications, resources}`. Nothing is audited.
- A confirm with other counts gets the fresh preview. A blocked change is still refused at confirm by
  `planMove`.

Tokens are deliberately left alone (owner decision, 2026-10-11): refresh tokens and grants are not revoked.
They fail against the new bucket and would work again if the project moved back, and issued access tokens
verify until they expire. The preview says so instead.

The audit entry records the destination as `bucketId` and the previous bucket as `formerBucketId`, so the
change appears in both buckets' trails ([[admin-audit-trail]]). In the console the change lives on the
project's Settings tab, in the Bucket card. The bucket's Overview only starts it ("Use in a project…").

## Who may move what

- **Leaving a group** needs an owner of it: taking a container away removes every other member's access.
- **Joining a group** needs only membership: any member may already create containers there, so receiving
  one grants nothing new. The owner chose this rule (spec Q2).
- **Never a destination**: another administrator's personal group, Super administrators, and the group the
  container is already in. **Never moved**: the administrators' bucket, the default bucket (every tenant's
  bucket-less projects sign into it) and the console's own project.

`loadDestination` (`lib/admin/ownership/destination.ts:27`) refuses in an order that reveals nothing.
Membership is checked before anything about the group's kind is said, so a caller outside the destination
gets the same answer as for an unknown id. The project route refuses `type === 'admin'` explicitly
(through `mayMoveProject`, `lib/admin/auth/can.ts`), because `loadProject` admits a super administrator to
the console's project. The bucket route checks `isUndeletableBucket` before loading.

Since spec 079 both routes decide the caller's right — the `move` flag the console and agents are shown —
before the destination and the source rule below: for a project, owning its group; for a bucket, owning its
group or a group whose project uses it (`bucketCan`). A member without it gets 403, where before it could
get a 409 that described how the container was attached. `assertGroupOwner(from)` still runs after the
source rule, so a body-dependent case (moving a mixed-group bucket into the group of its stray project)
can still answer 403 to a caller the flag admitted.

## The source rule, and why a repeated move completes

`sourceGroupOf` (`destination.ts:70`) takes the owners of the bucket and of every project using it, drops
the destination, and requires exactly one group to remain:

- **none left** → 409 `already owned by this group`;
- **two or more** → 409, naming no group;
- **one** → that group is the source.

Dropping the destination first is what makes two awkward states repairable without a special path:

- a move that a standalone `mongod` left half-done, with the bucket in the destination and some projects
  still in the source;
- legacy data where a project is in a different group from its bucket. Moving the bucket into the project's
  group repairs it.

## One change, per backend

The write goes through `ContainerOwnershipStore` (`lib/adapters/types.ts:1740`). Business logic gets no
transaction from the adapter contract. Each method re-checks its precondition inside the write — every
owner involved is `from` or already `to` — and changes nothing otherwise.

| Backend | How the move is one change |
|---|---|
| PostgreSQL | one transaction, with the bucket row locked first |
| MongoDB, replica set | a transaction |
| MongoDB, standalone | ordered conditional writes: the bucket first, then its projects |
| Memory | no `await` between the check and the last write |

**Bucket first** on a standalone `mongod`, because the bucket's conditional write is the lock. Of two
racing moves only one finds the bucket still in a group it may leave. The real-database check for this
lives in `database/verify_container_ownership.ts`. The remaining half-done window is the declared
`container-move-atomicity` divergence (`lib/consts/storage_divergences.ts:85`). While it lasts, consent is
*not* waived for the bucket's clients, which is the safe direction. For the same reason the consent page
speaks of them as another group's apps (operator-registered) until the projects follow, which is the
cautious reading too.

The store finds the bound projects inside the write instead of taking a list. A project bound a moment
earlier therefore still moves.

## A binding that races a move

One race remains:

1. a bind request reads the bucket while it is still in the source group;
2. the move commits;
3. the bind writes.

The bind route re-reads the bucket after its write (`projects/routes.ts:358`). If the owners now differ, it
restores the previous binding and the declaration namespace, then answers the same 409. Whichever of the
two writes comes second sees the other, so this needs no lock.

The reverted bind still leaves its `project.bucket.assign` entry. An entry records that an authorized actor
reached the change, not that the change held ([[admin-audit-trail]]).

## The trail sees both groups

A move writes one entry:

- `ownerGroupId` is the group the container joined;
- `formerOwnerGroupId` is the group it left (`types.ts:606`, `lib/admin/audit/record.ts:199`).

The group-scoped read matches either field in all three backends:

- memory: `admin_audit_query.ts:90`;
- MongoDB: `adminAuditStore.ts:54`;
- PostgreSQL: `adminAuditStore.ts:75`.

Each field has its own index (`storage_inventory.ts:731`).

A second field is used rather than a second entry, because one action writes one entry and audit-first
could not write two atomically. Entries written before a move keep the group that owned the container at
the time; they are never re-derived. The joining group sees the container's history from the move onward.

**`cascade` is no longer only a deletion's.** A bucket move counts the projects that moved with it there
(`{ projects: n }`), and the personal-group migration counts the members it removed. One entry still covers
everything the action reached, as [[deletion-and-revocation]] argues for deletions. The verb belongs to the
action, though, so the console's column is now **Also affected** and derives the word from `action`: moved,
removed or destroyed (`lib/admin/ui/pages/Audit.tsx`). It was titled "Also destroyed", and a move read
there as two destroyed projects — found while walking the console through a move.

## The agent sees the preview

Both routes refuse without `confirm: true`, answering 409 with a preview that names the projects. The MCP
gate's consequence report reads no entity state, so it cannot provide that list itself. Until this change,
`toOutcome` reduced every 409 to `conflict: the operation was refused`, so an agent never saw a preview,
`bucket_address_change`'s included. It now passes a `confirmationRequired` body through whole as `preview`
(`lib/mcp/result.ts:79`).

A confirmation token binds the arguments, and `confirm` is one of them. An agent therefore confirms the
preview and the move separately. Both tools are `high`.

## Making personal groups personal on upgrade

Migration `2026-10-09-personal-groups-single-member` (`lib/consts/migrations.ts:757`) removes every member
of a personal group except its first, and makes that one the owner. Before writing the group, it writes one
`group.member.remove` entry per group with:

- the deterministic id `<migration>:<group>`, so a rerun inserts nothing;
- actor `system:migration` (`lib/consts/admin_audit_routes.ts:623`);
- `cascade: { members: n }`.

The entry counts the removed members and names none. The trail records field names and counts, never
values, and the route's own removal entry does not name the removed user either. An operator who needs to
know who will lose access lists the shared personal groups before upgrading. The migration is not
reversible, and `db:migrate --plan` says so.

## Known residual race

A move into a group that is being deleted at the same moment can leave the container owned by a group that
no longer exists. Group deletion checks for emptiness, then destroys (`lib/admin/groups/routes.ts`, the
`DELETE /admin/api/groups/:id` handler). The same race already exists for creating a container into a group
being deleted. A super administrator can move the orphan out. It is recorded here rather than fixed.

## Related

- [[group-ownership]] — the ownership model this moves within, and why a personal group is no longer
  shareable.
- [[admin-audit-trail]] — the two-field group-scoped read.
- [[admin-mcp-control-plane]] — the two `high` tools and the preview pass-through.
- [[postgresql-backend]] — the migration machinery and the divergence register.

Verified against [[oauth-server-codebase]].
