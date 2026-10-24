---
type: concept
title: 'Monthly active users per project'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-15
---

# Monthly active users per project

Every project counts, per UTC month and per UTC day, the distinct end users it **issued tokens to**
(spec 076). The Default and administrators' projects are counted like any other. Each figure is broken down
by how the person was active — `local` (a sign-in at this server), `federated` (through an upstream
provider), `renewal` (tokens without a fresh sign-in) — and by whether a directory provisioned them. Since
spec 102 a project's plan reads the current month's figure for its soft cap: at the cap, new self-service
accounts are paused and no sign-in is ever refused ([[plans]]). Nothing is charged here.

A project is stored as a bucket (`UserBucket`) and its owning team as an administrator group (`Group`); the
stores and the code keep those names. What a reader sees changed in spec 100: the activity answers carry
`projectId` (a row, a sharp change, one project's figures), `projects` (the overview's rows), `activeProjects`
(the instance summary), `projectIds` (a customer's) and the customer's `teamId` (`lib/activity/overview.ts:23-109`),
where they carried `bucketId`, `buckets`, `activeBuckets`, `bucketIds` and `groupId`.

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

## The project is the one `findAccount` resolved — never the token's `bucketId`

The token's `bucketId` records where the flow *started*. At the root that is not the population: the Default
project, the administrators' project and every unaddressed project are all served there, so a console session
reused silently records the Default project. Counting by it would move administrators into the Default
project's figure. `findAccount` already resolves the population (`resolveBucketForRequest`, with the resource,
which once cost a 500 when it was left out), so it returns `bucketId` and `provisioned` on the account
(`lib/addon/account.ts:78-79`) and the recorder reads those. An overriding resolver must return both — the
type requires it.

## Which kind: the artifact records it, because only the request knows

`signIn: 'local' | 'federated'` is a new optional field on `AuthorizationCode`, `DeviceCode` and
`BackchannelAuthenticationRequest` (`lib/models/mixins/stores_auth.ts:27`), set where each is created
(`lib/helpers/process_response_types.ts:41`, `lib/actions/authorization/device_user_flow_response.ts:34`,
`lib/actions/authorization/backchannel_result.ts:155`). Absent means renewal, which is how an artifact
written before the field reads — no migration. Never on a refresh token: its use is a renewal by definition.

**The trap: a sign-in is often not in the result that produces the artifact.** When consent follows the
sign-in — always for a device approval — the code is minted when the *consent* interaction resumes, whose
`result` holds only the consent. The sign-in is the previous interaction's result, which the new one carries
as `lastSubmission` (`lib/actions/authorization/interactions.ts:130`). `signInOf` reads both
(`lib/activity/kinds.ts:21-29`); reading `result.login` alone counted every device approval as a renewal.
Comparing `authTime` with the code's `iat` cannot work either: a slow consent screen and a reused session
look the same by time. `federated` comes from the session's `upstream`, never from `acr`, which an operator
can rename.

## Marks instead of counters, so the figure is exact with no transaction

`activityMarks` holds one record per (project, period, account), `_id` `${bucketId}|${period}|${accountId}`,
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
(`lib/activity/closer.ts:25`, started from `lib/index.ts:297` — not beside the PostgreSQL sweeper, because it
reads the project store and starting it inside the adapter module is the cycle [[model-graph-import-order]]
describes); the first read of an ended, unfrozen period (`readPeriods`, `lib/activity/read.ts:55`); and
project deletion. A period is closable five minutes after it ends (`CLOSE_GRACE_MS`,
`lib/activity/periods.ts:19`), which absorbs clock skew between instances. The closer visits only the
previous month and the last 41 days, asking each for the projects with marks — never thirteen months of marks
every hour — with a `$group`, because the Stable API refuses `distinct` ([[mongodb-test-fidelity]]). A stored
figure is final wherever it exists, an open period included: an open period has one only when its project was
deleted. A quiet period is zero, computed rather than stored; one before `max(bucket.createdAt,
countingSince)` is absent, never zero.

## Retention, and why history is unowned

A month's marks expire thirteen months after it ends, a day's forty days after (`lib/activity/periods.ts:22-23`);
figures are permanent. Both areas are **store areas with no owner** (`lib/consts/storage_inventory.ts:786-804`):
an area naming an account owner is swept by `cascadeForAccount` on every end-user and project deletion, and a
month a deleted person was active in must still count them. The project delete route does not sweep them
either. Instead it calls `retire` before destroying anything (since spec 090 in `destroyBucket`,
`lib/admin/buckets/destroy.ts`, run by Delete now and by the 30-day pass — [[project-soft-delete]]): the
tombstone first — if it cannot be written the deletion does not begin, because without it no loader could
ever list the history again — then a best-effort freeze of the open month and day, which the closer would
otherwise do later under the tombstone's name.

## Reading it

`GET /admin/api/projects/:id/activity` (`lib/admin/activity/routes.ts:173`; MCP `project_activity_get`) uses
the owning-team check (`loadBucketForEdit`, `:139`), not the broader one a project's page uses. Until spec 099
they differed: a team that only owned an old Project (a retired project) signing into this project administered
its users, not its plan. With old Projects gone both admit exactly the members of the project's team. A super
administrator may read **any** project's figures there — the reserved projects and deleted ones, from their
tombstones (`bucketToRead`, `:123`, since spec 077) — because every one of them is already in their overview.
**Since spec 091 the team a deleted project's tombstone names (stored `ownerGroupId`) may read it too**
(`heldDeletedBucket`, `lib/admin/auth/can.ts`): its active users counted in that team's months, and without it
the team's sum for the month of the deletion would disagree with the super administrator's. Anyone else falls
through to `loadBucketForEdit`, so the refusal is the one an id that never existed gets, byte for byte; a
tombstone written before 077 names no team and stays a super administrator's alone. Membership is read per
request: someone who leaves the team loses the history. Since spec 086 the answer names the project (`name`,
beside `projectId`) and, for a deleted one, `deletedAt` and `lastOwner` (`{ teamId, label }`), both from the
tombstone (`:190-202`).

**In the console (spec 086).**
- The project's Activity tab is built from the Usage dashboard's own parts: charts, the change rule and the CSV
  cell rules. The month lives in the address and is replaced on change, never pushed. Chart or Table is a
  per-browser preference.
- Usage links each project to its Overview and its Activity tab at the dashboard's month. The project drawer is
  gone.
- A deleted project's history has a page, `/admin/usage/projects/:p`, for whoever may read it (above). Its
  address until spec 100, `/admin/usage/buckets/:b`, redirects there (`formerPattern`,
  `lib/admin/ui/frame/routes.ts:361-375`).
- Opening a deleted project's own address tells them when it was deleted and links to that history. Since spec
  091 every caller makes that read; the server's refusal leaves everyone else the ordinary no-access page, so
  the project stays indistinguishable from one that never existed.

`GET /admin/api/activity` (`:227`) is the Usage overview, and since spec 077 the whole Usage
dashboard in one answer: every project (reserved and deleted included, in `projects`) with its **customer** —
the owning team (`teamId`), labelled by the shared `groupLabel` (`lib/admin/groups/label.ts`) — its thirteen
months and the days of the month and of the month before, plus each customer's sums and contacts (its owners'
emails, not its plain members'), the instance's totals, and the projects that changed sharply. The answer's
types and every sum over it live once in `lib/activity/overview.ts`, a type-only-import module the console
bundles too: the route computes the totals over every project (the agent's answer), and the console recomputes
them over the rows its search and filters leave, with the same functions, so a total on screen describes the
rows on screen.

**Every administrator reads it since spec 091**, under Organisation in the menu. For anyone but a super
administrator the route narrows the projects **before** reading anything: the live ones `holdsBucket` admits
(member of the owning team, any role — the predicate behind each project's Activity tab) and the tombstones
`heldDeletedBucket` admits, the reserved projects never. Customers, contacts, the "instance" totals and the
sharp changes are then computed over those rows by the same functions, so no other tenant's figure is ever
summed into the answer; for such a caller `instance` means "my projects". A super administrator's answer is
unchanged. The MCP tool `activity_overview` follows (no longer `superAdminOnly`).

Rules the code holds and a reader can get wrong:

- **A customer's figure is a sum, not a distinct count** (`sumFigures`, `lib/activity/overview.ts:135`). Each
  project is its own population, so a person in two projects is two accounts.
- **The kinds are never stacked into the total.** `tallyOf` counts a person once in `total` and once in *each*
  kind they used, so local + upstream + renewal ≥ total; the charts draw them beside the total.
- **A change is only computed between two final figures** (`changeBetween`): a month in progress against a
  finished one reads as a fall that has not happened. "Sharp" (`sharpChanges`, `:268`) compares the last two
  closed months and needs both ≥ 20 people and ≥ 30 % of the earlier figure (`:121`).
- **The customer is read live, not copied** (`resolveCustomers`, `lib/admin/activity/customers.ts:55`), so a
  rename shows at once. A deleted project's tombstone keeps `ownerGroupId` and `ownerLabel`
  (`lib/adapters/types.ts:1902`, written by `tombstoneOf`, `lib/adapters/activity_records.ts:38`) for the day
  its team is deleted too; a tombstone written before 077 has neither and reads as an unknown customer.
  A moved project's past months show under its current owner — which owner a past month is charged to is
  billing's question.
- **One project that cannot be read does not fail the page.** The per-project fallback in `readPeriodForBuckets`
  marks that project `unavailable` (`lib/activity/read.ts:190`) and the sums say they exclude it; a failed
  listing for a whole period still fails the answer.
- **The CSV export is built in the browser and is formula-safe** (`lib/admin/ui/activity/csv.ts:31`): customer
  names are chosen by customers, and a cell beginning with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
  Its header opens `month,project_id,project,customer,customer_kind` (`:12-17`); until spec 100 the second and
  third columns were `bucket_id,bucket`.

The overview names administrators (contacts, personal teams' labels), never an end user who was counted:
spec 076's "no email address" test was re-anchored to the counted accounts for that reason. Neither read is
audited; both are MCP tools, `project_activity_get` and `activity_overview` (`lib/mcp/catalogue.ts:379`, `:392`). Nothing lists who was counted. That list was specified and deferred to the billing feature: it would be the one audited read, and
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
