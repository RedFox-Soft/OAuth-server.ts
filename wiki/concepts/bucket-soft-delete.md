---
type: concept
title: 'Bucket soft delete: Delete switches a bucket off for 30 days, then the server destroys it'
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-10-12
updated: 2026-10-12
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:deletion-and-revocation
    - predicate: depends_on
      object: concept:bucket-is-an-issuer
    - predicate: relates_to
      object: concept:bucket-workspace
    - predicate: relates_to
      object: concept:admin-mcp-control-plane
---

# Bucket soft delete

Since spec 090, `DELETE /admin/api/buckets/:id` does not destroy a bucket. It runs every check the deletion ran
before, then sets `UserBucket.deletion` (`scheduledAt`, `purgeAt` = 30 days later, `scheduledBy`;
`lib/adapters/types.ts`, constants in `lib/consts/bucket_deletion.ts`). From that moment the bucket answers nobody,
and nothing in it is touched:
- `POST …/restore` removes the field, and the bucket is back exactly as it was.
- `POST …/purge` ("Delete now") destroys a scheduled bucket at once.
- An hourly pass destroys the ones whose date has passed.

The period is fixed by the owner's decision; there is no setting.

## There is no single place to switch a bucket off

The first idea, refusing in whatever function "finds the bucket", does not work, because requests find a bucket in
two unrelated ways.

- **By address.** `bucketAtAddress` / `bucketAtHost` answer null for a scheduled bucket unless the caller asks
  `includeScheduled` (`lib/admin/auth/bucketAddress.ts:199-252`), so `requestBucketFor` throws `UnknownBucket`.
  Every door at the bucket's own path or host therefore answers 404, exactly as an absent address does:
  discovery, JWKS, `/auth`, everything behind `AuthPlugin` (token, introspection, revocation, PAR), device, CIBA,
  registration, end-session, userinfo and SCIM.
- **By a stored id.** Grants never compare an artifact's bucket with the address, so a scheduled bucket's refresh
  token would still be redeemed at the root `/token`. The default `findAccount` answers nothing when the bucket it
  resolved is scheduled (`lib/addon/account.ts:65`), which closes every grant and userinfo anywhere. Four doors
  that read a bucket from a stored id check for themselves:
  - interactions, for both the bucket the interaction began at and the sign-in bucket (`lib/interactions/index.ts:734`);
  - the federation callback (`lib/federation/routes.ts:145`);
  - the verification links (`lib/verification/challenge.ts:152,258`);
  - the password-reset links (`lib/password_reset/challenge.ts:162`).

  The check that keeps `/admin` and `/mcp` off a tenant's hostname (`lib/plugins/instancePlane.ts`) counts a
  scheduled bucket too, so the console is not served at its host.

**A `findAccount` override takes the check over**, the same way it already takes over `canSignIn`.

**Introspection at the bucket's own address is a 404, not `active: false`.** It is one of that address's doors.
Every other issuer of the server answers `active: false` through ordinary per-issuer isolation.

**A JWT access token a resource server verifies on its own lives to its `exp`.** Only a key set fetched afresh
fails. The deletion dialog says so.

## Caches expire after a minute

The address caches (`bySlug`, `byHost`, `byId`) were process-local Maps with no expiry. On a second instance a
scheduled bucket would have kept answering until a restart. Entries now live 60 seconds (`CACHE_LIFETIME_MS`,
`bucketAddress.ts:49`), and `bucketIsScheduled` keeps a fresh read on the same lifetime (`:142`). The instance that
schedules or restores calls `forgetBucketAddresses()` and changes at once; every other instance converges within a
minute. The same bound now applies to an address change or a deletion on another instance, which had none before.

## Signals that only end access still act

Back-channel logout and global token revocation resolve with `includeScheduled: true`
(`lib/upstream_signals/back_channel_logout.ts:139`, `global_token_revocation.ts:102`). They destroy sessions while
the bucket is off. A restore therefore cannot resurrect a session the upstream ended while nobody could deliver the
signal.

## One guard refuses every administrative write

`scheduledBucketGuard` (`lib/admin/buckets/scheduled_guard.ts`, mounted at `lib/admin/routes.ts:101`) is an
`onBeforeHandle` keyed on the **mounted route pattern**. It refuses every non-GET route under
`/admin/api/buckets/:id` except `/restore` and `/purge` with 409 "scheduled for deletion on <date>. Restore it first."

- **Why not the loaders.** The three bucket loaders serve reads and writes alike, so a check there would need an
  opt-out at a dozen reads.
- **Keyed on the pattern, not a list.** A route added later under the prefix is guarded without anyone remembering.
  `test/admin/bucket_scheduled_writes.spec.ts` enumerates the mounted routes to prove it.
- **Agents are covered.** MCP dispatches into the same routes, so the same guard refuses an agent.
- **Strangers learn nothing.** The guard answers only a caller who may read the bucket. Anyone else falls through
  to the handler's own 403/404, so a 409 never tells a stranger that a bucket exists and is scheduled.
- **Outside the prefix.** Project assignment (`PUT /admin/api/projects/:id/bucket`, and creating a project with
  `bucketId`) checks the same state itself.

The console folds the state into `bucketCan` once (`lib/admin/ui/frame/can.ts`), so every panel turns read-only
without a change of its own. The server keeps state out of its `can` flags, as `lib/admin/auth/can.ts:15-17` asks.

## Destruction: one procedure, claimed, recorded once, record last

`destroyBucket` (`lib/admin/buckets/destroy.ts:48`) is the old DELETE body, moved. Delete now and the pass both
call it.

1. **Claim.** `claimPurge` (`:56`) is a compare-and-set that takes a 15-minute claim. Only the holder proceeds, so
   two instances, or a pass racing an administrator, cannot both destroy.
2. **Audit once.** `bucket.purge` is written only while `deletion.purge.recordedAt` is unset (`:103`), then marked.
   A retried destruction is not recorded twice.
3. **Usage tombstone.** It is written before anything is destroyed. If it fails, nothing is deleted.
4. **Contents.** Accounts with their cascade, keys, provisioning connections, groups and the user area.
5. **The bucket record LAST** (`:195`). The old route destroyed the record before keys, connections and groups. A
   failure in between then orphaned them, with nothing left to find them by. Now a failure leaves a
   still-scheduled, still-silent bucket, and the next pass finishes it once the claim lapses.

The pass (`purgeDueBuckets` / `startBucketPurger`, `lib/admin/buckets/purge_pass.ts:17,54`) follows the
`startCloser` pattern, started in `lib/index.ts:294` outside tests. It records as
`RETENTION_ACTOR = 'system:retention'` (`lib/consts/admin_audit_routes.ts:749`) through `recordSystemAudit`. The
entry carries `ownerGroupId`, so the owning group reads it like its own deletion.

**A destruction that throws gives its claim back** (`releasePurge`, `:71`). Only while the claim is still the one
it took, and keeping `recordedAt`, so the administrator's next Delete now starts at once instead of being told for
15 minutes that the bucket is already being deleted. Only a process that dies mid-way leaves the claim to lapse.
The first version kept the claim, and a failed Delete now could not be retried for a quarter of an hour.

**A failed destruction can leave a `bucket.purge` entry for a bucket that still exists.** The audit entry is written
before the usage tombstone, by the trail's contract. If the tombstone cannot be kept, nothing is destroyed but the
entry stands, and a later restore reads as `bucket.purge` followed by `bucket.restore`. The reverse order is worse:
a tombstone written before an audit write that then fails lists a live, restorable bucket as deleted in Usage.

## Agents

- `bucket_restore` is published as `high`: it only gives access back, but it gives it back to everyone.
- Scheduling (`DELETE`) and `POST …/purge` stay withheld. The reason is the old deletion's: left alone, a
  scheduled bucket ends in that same destruction (`lib/mcp/catalogue.ts`).
- `bucket_get` and `bucket_list` carry `deletion`.

## Related

- [[deletion-and-revocation]] — what a container deletion destroys; the purge is that deletion, moved.
- [[bucket-workspace]] — the Danger zone and the delete dialog this changes.
- [[bucket-is-an-issuer]] — why a scheduled issuer's discovery and key set answer as absent.
- [[admin-mcp-control-plane]] — the withheld operations and `bucket_restore`.
- [[admin-audit-trail]] — the system actor.
