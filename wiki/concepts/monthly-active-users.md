---
type: concept
title: 'Monthly active users per bucket'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-10
---

# Monthly active users per bucket

Every bucket counts, per UTC month and per UTC day, the distinct end users it **issued tokens to**
(specs/076). The default and administrators buckets are counted like any other. Each figure is broken down
by how the person was active — `local` (a sign-in at this server), `federated` (through an upstream
provider), `renewal` (tokens without a fresh sign-in) — and by whether a directory provisioned them. Plans
will be priced per bucket on these figures; none exist yet, so nothing is refused or charged here.

## What counts, and why that definition

Activity is a token issued on the person's behalf, recorded at one place: `noteActivity(oidc)` in
`executeGrant` (`lib/actions/grants/index.ts:102`). Auth0, Entra External ID, Supabase, FusionAuth and
ZITADEL all count token issuance, refresh and silent authentication included; counting interactive sign-ins
only would make an application living on long refresh tokens look unused. Every edge case then falls out
with no rule of its own: a failed, throttled or abandoned sign-in issued nothing; a sign-in whose code is
never redeemed issued nothing; `client_credentials` sets no `Account` and is nobody's activity.

**It is a call, not an `eventBus` listener.** The bus is a synchronous emitter: a listener that threw would
fail a request whose tokens were already saved, and nobody would see an async listener's rejection. No module
in `lib/` subscribes to the bus at all — it is the downstream applications' seam.

## The bucket is the one `findAccount` resolved — never the token's `bucketId`

The token's `bucketId` records where the flow *started*. At the root that is not the population: the default
bucket, the administrators bucket and every unaddressed bucket are all served there, so a console session
reused silently records the default bucket. Counting by it would move administrators into the default
bucket's figure. `findAccount` already resolves the population (`resolveBucketForRequest`, with the resource,
which once cost a 500 when it was left out), so it returns `bucketId` and `provisioned` on the account
(`lib/addon/account.ts:78-79`) and the recorder reads those. An overriding resolver must return both — the
type requires it.

## Which kind: the artifact records it, because only the request knows

`signIn: 'local' | 'federated'` is a new optional field on `AuthorizationCode`, `DeviceCode` and
`BackchannelAuthenticationRequest` (`lib/models/mixins/stores_auth.ts:27`), set where each is created
(`lib/helpers/process_response_types.ts:41`, `lib/actions/authorization/device_user_flow_response.ts:34`,
`lib/actions/authorization/backchannel_result.ts:136`). Absent means renewal, which is how an artifact
written before the field reads — no migration. Never on a refresh token: its use is a renewal by definition.

**The trap: a sign-in is often not in the result that produces the artifact.** When consent follows the
sign-in — always for a device approval — the code is minted when the *consent* interaction resumes, whose
`result` holds only the consent. The sign-in is the previous interaction's result, which the new one carries
as `lastSubmission` (`lib/actions/authorization/interactions.ts:126`). `signInOf` reads both
(`lib/activity/kinds.ts:21-29`); reading `result.login` alone counted every device approval as a renewal.
Comparing `authTime` with the code's `iat` cannot work either: a slow consent screen and a reused session
look the same by time. `federated` comes from the session's `upstream`, never from `acr`, which an operator
can rename.

## Marks instead of counters, so the figure is exact with no transaction

`activityMarks` holds one record per (bucket, period, account), `_id` `${bucketId}|${period}|${accountId}`,
with the set of kinds seen. A mark is one single-document upsert — `$setOnInsert` + `$addToSet` on MongoDB
(`lib/adapters/mongodb/activityStore.ts:80-104`), `ON CONFLICT … jsonb_set` on PostgreSQL
(`lib/adapters/postgres/activityStore.ts:60-82`) — and an open period's figure is **counted from its marks**
when read. The obvious design (insert-if-absent a mark, then increment a counter) is two writes in two
documents: a crash between them undercounts forever, and on a standalone `mongod` nothing closes that gap.
Counting marks has no second write to lose, so there is no transaction and no divergence entry. PostgreSQL
uses containment (`@>`) rather than the `?` operator.

## Freezing, and why a closed figure never changes

`activityFigures` holds the figure of each ended period, written **insert-if-absent** — the first writer
wins, nothing rewrites it. Three things freeze, all idempotent: an hourly closer
(`lib/activity/closer.ts:25`, started from `lib/index.ts:288` — not beside the PostgreSQL sweeper, because it
reads the bucket store and starting it inside the adapter module is the cycle [[model-graph-import-order]]
describes); the first read of an ended, unfrozen period (`readPeriods`, `lib/activity/read.ts:55`); and
bucket deletion. A period is closable five minutes after it ends (`CLOSE_GRACE_MS`,
`lib/activity/periods.ts:19`), which absorbs clock skew between instances. The closer visits only the
previous month and the last 41 days, asking each for the buckets with marks — never thirteen months of marks
every hour — with a `$group`, because the Stable API refuses `distinct` ([[mongodb-test-fidelity]]). A stored
figure is final wherever it exists, an open period included: an open period has one only when its bucket was
deleted. A quiet period is zero, computed rather than stored; one before `max(bucket.createdAt,
countingSince)` is absent, never zero.

## Retention, and why history is unowned

A month's marks expire thirteen months after it ends, a day's forty days after (`lib/activity/periods.ts:22-23`);
figures are permanent. Both areas are **store areas with no owner** (`lib/consts/storage_inventory.ts:777-795`):
an area naming an account owner is swept by `cascadeForAccount` on every end-user and bucket deletion, and a
month a deleted person was active in must still count them. The bucket delete route does not sweep them
either. Instead it calls `retire` before destroying anything (`lib/admin/buckets/routes.ts:724`): the
tombstone first — if it cannot be written the deletion does not begin, because without it no loader could
ever list the history again — then a best-effort freeze of the open month and day, which the closer would
otherwise do later under the tombstone's name.

## Reading it

`GET /admin/api/buckets/:id/activity` (`lib/admin/activity/routes.ts:155`) uses the owning-group check
(`loadBucketForEdit`), not the broader one a bucket's page uses: a group that only owns a project signing
into the bucket administers its users, not its plan. A super administrator may read **any** bucket's figures
there — the reserved buckets and deleted ones, from their tombstones (`bucketToRead`, `:115`, since spec 077) —
because every one of them is already in their overview; the group that owned a deleted bucket gets the
missing-bucket answer, as from every other route.

`GET /admin/api/activity` (`:188`) is the super administrator's overview, and since spec 077 the whole Usage
dashboard in one answer: every bucket (reserved and deleted included) with its **customer** — the owning
group, labelled by the shared `groupLabel` (`lib/admin/groups/label.ts`) — its thirteen months and the days
of the month and of the month before, plus each customer's sums and contacts (its owners' emails, not its
plain members'), the instance's totals, and the buckets that changed sharply. The answer's types and every
sum over it live once in `lib/activity/overview.ts`, a type-only-import module the console bundles too: the
route computes the totals over every bucket (the agent's answer), and the console recomputes them over the
rows its search and filters leave, with the same functions, so a total on screen describes the rows on screen.
Rules the code holds and a reader can get wrong:

- **A customer's figure is a sum, not a distinct count** (`sumFigures`, `lib/activity/overview.ts:135`). Each
  bucket is its own population, so a person in two buckets is two accounts.
- **The kinds are never stacked into the total.** `tallyOf` counts a person once in `total` and once in *each*
  kind they used, so local + upstream + renewal ≥ total; the charts draw them beside the total.
- **A change is only computed between two final figures** (`changeBetween`): a month in progress against a
  finished one reads as a fall that has not happened. "Sharp" (`sharpChanges`, `:268`) compares the last two
  closed months and needs both ≥ 20 people and ≥ 30 % of the earlier figure (`:121`).
- **The customer is read live, not copied** (`resolveCustomers`, `lib/admin/activity/customers.ts:55`), so a
  rename shows at once. A deleted bucket's tombstone keeps `ownerGroupId` and `ownerLabel`
  (`lib/adapters/types.ts:1898`, written by `tombstoneOf`, `lib/adapters/activity_records.ts:38`) for the day
  its group is deleted too; a tombstone written before 077 has neither and reads as an unknown customer.
  A moved bucket's past months show under its current owner — which owner a past month is charged to is
  billing's question.
- **One bucket that cannot be read does not fail the page.** The per-bucket fallback in `readPeriodForBuckets`
  marks that bucket `unavailable` (`lib/activity/read.ts:190`) and the sums say they exclude it; a failed
  listing for a whole period still fails the answer.
- **The CSV export is built in the browser and is formula-safe** (`lib/admin/ui/activity/csv.ts:31`): customer
  names are chosen by customers, and a cell beginning with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.

The overview names administrators (contacts, personal groups' labels), never an end user who was counted:
spec 076's "no email address" test was re-anchored to the counted accounts for that reason. Neither read is
audited; both are MCP tools (`lib/mcp/catalogue.ts:354`, `:367`). Nothing lists who was counted. That list was specified and deferred to the billing feature: it would be the one audited read, and
an audited GET has no precedent — `AuditedMethod` excludes GET, and three guards and the site's "Mutations"
section assume a GET writes nothing — so it should be a POST when it comes. Eden revives any string that
parses as a date, so a test reading a day's period (`2031-03-15`) through it gets a `Date`; read those
responses as plain JSON.

## Hot path

`noteActivity` never awaits on the response path. A process-wide `QuickLRU` of 50 000 keys
(`lib/activity/note.ts:27`) skips a person already recorded today in that kind, so a client refreshing every
few minutes costs one pair of upserts per person per day per instance; correctness never depends on it. A
failed write is logged unconditionally and recorded as the error store's seventh capture site
([[error-store-capture-sites]]).
