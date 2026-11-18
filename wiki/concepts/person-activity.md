---
type: concept
title: "A person's activity: sign-ins, what the proxy refused and what people used"
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-16
updated: 2026-11-18
---

# A person's activity: sign-ins and what the proxy refused

Spec 133 ("5A" of the visit log). What this server **decided** about a person, kept per person for 90 days and shown on
the person's Activity tab: every sign-in, every failed sign-in where the account was already found, every stop on the
sign-in path, and every "Asked to sign in again" and "Refused" of an app behind the proxy or an API checked at it.
Since spec 134 ("5B", 2026-11-16) what a person **used** behind the proxy is kept too: one row a day for each app,
or API and application, that let them through (see "What a person used" below). The module is
`lib/person_activity/`; the area is `personActivity`.

## What is recorded, and from where

- **A successful sign-in** is noted by the callers of `getResume`, not by `resume.ts`, which never sees the request:
  `noteResumedSignIn` in `lib/interactions/index.ts:309`, called from `resume()` (`:375`) and the device completion
  (`:478`), only when no confirmation page was answered. `completeSignIn` of an app behind the proxy is deliberately
  not a place: it would count the sign-in twice, with the proxy's address. The method is `password`,
  `password_code` (acr multi-factor) or `provider`; a sign-in through `proxy.<bucketId>` keeps the origin of its
  validated redirect URI, so the read can name the app.
- **Failures and stops** only where the account was already read: wrong password, `canSignIn` false (locked or
  deactivated), unverified address, wrong code (not a reused one), the code-required page, a provider sign-in into a
  closed account (`lib/federation/routes.ts`, and the hand-off path in `lib/interactions/index.ts`). Never the
  throttle, the attacker list or the closed password door: there the server deliberately does not read the account
  ([[shared-attacker-list]]), and an unknown email costs and records nothing.
- **At the proxy**: `noteAppCheck` after `emitDecision` (`lib/behind_proxy/check.ts:488`, `:497`); `noteForPerson` in
  `lib/behind_proxy/api_check.ts:91`, under the API's own project (a token never names a person of another,
  `api_person.ts`). `behind_proxy.api_decision` gained `accountId`. Recording is a direct call, not a bus listener: a
  row needs the proven address, which never goes on an event.

## Invariants

- **No caller text reaches the store.** Reasons are a closed union; a tool is recorded as the tools-table row an
  administrator named, or `*another` (`recordedTool`, `lib/person_activity/record.ts:330`), never the decoded
  `Mcp-Name`; the browser is two enums from an own bounded classifier (`device.ts`), never the raw `User-Agent`; the
  rule is `decision.rule`, the configured path, never the request path. A property test generates hostile text
  (`test/person_activity/no_client_text.spec.ts`). Words for every reason live once in `words.ts`, a `Record` over the
  union, read by the console and the MCP tool alike.
- **Addresses.** A sign-in keeps `personAddressOf(callerAddressOf(request))` (`address.ts:23`): IPv4-mapped read as
  IPv4, never unattributed, private or a trusted proxy's own address; behind a proxy the server does not trust it is
  the proxy's address, exactly as rate limits see it. An app row keeps the address only when `proves(flags)`; an API
  row never. Country and categories come from `factsAt` on the local snapshot, only when known ([[network-facts]]).
  Since spec 136 (2026-11-17) a row with an address may also carry `lookup` (AS number and name, region code and
  name, city), added by `withLookups` in the flush between `withoutTheDeleted` and the write
  (`lib/person_activity/flush.ts`), never on a request. It follows its address when rows merge (`lookupAfter`,
  `lib/adapters/person_activity_rows.ts`; MongoDB writes address rows through an update pipeline for it)
  ([[address-lookup]]).
- **Notes never touch the datastore.** Every `note*` is a synchronous `Map` operation that never throws
  (`buffer.ts:63`), so the password door costs a found and a missing account the same reads (tested).
- **The administrators' project keeps sign-ins only** (spec 137): `recording(bucketId, kind)` (`record.ts:50`) lets
  `ADMIN_BUCKET_ID` through for `kind: 'signIn'` and nothing else, so no proxy, API or use row is ever noted there.
  Until spec 137 the project was not recorded at all (S15), which left a stolen administrator password invisible until
  the thief changed something; the flush now checks its rows against the administrators' user store like any
  project's. The sign-in itself is still never an audit entry ([[admin-console-signin]]).

## The buffer and the flush

- Per kind of note an instance budget, and per project a quota (`PERSON_ACTIVITY_BUDGETS`,
  `lib/consts/person_activity.ts`); a note over either is folded into the project's overflow row for the day
  (`accountId: '*'`, `reason: 'other'`, `buffer.ts:43`), which the timeline reports as "too busy … may be missing
  entries". A successful sign-in is never budgeted. Budgets are per process and multiply with processes.
- Every 60 s (`startPersonActivity`, `flush.ts:113`) the map is swapped out; rows of people who no longer exist are
  dropped by one `findMany` per project (`withoutTheDeleted`, `flush.ts:23`); rows go in chunks of 500. A failed chunk
  is counted and **never retried**: the write adds, so a retry double-counts. MongoDB is one unordered `bulkWrite` per
  chunk (`$setOnInsert` / `$inc` / `$min` / `$max`, an 11000 retried once); PostgreSQL is one transaction per chunk
  with rows sorted by id, so two processes lock in one order and cannot deadlock (40P01). The partial-chunk
  difference is declared (`person-activity-partial-chunk`, `lib/consts/storage_divergences.ts:136`).
- Rows other than sign-ins are rolled up per UTC day, place, outcome and reason (`activityId`, `buffer.ts:35`); a
  rolled-up row's address is the latest write's, last writer wins on both backends.
- Its own SIGTERM/SIGINT drain, 2 s bound (`flush.ts:93`): a crash loses up to a minute, and the site says so.

## Keeping and deleting

- The area is **unowned** (`storage_inventory.ts:803`): an account owner would mean swept by every lock, deactivation
  and "Sign out everywhere", the moment an administrator needs it. Deleting a person (`removeEndUser`,
  `lib/end_users/service.ts:339`, the path of console, bulk and SCIM deletion) and destroying a project
  (`lib/admin/buckets/destroy.ts:236`) remove it by hand through `forget.ts`, which also drops this process's notes
  and deletes once more two intervals later for a row another process wrote in between.
- 90 days after the last write, sliding (`expiresAt` raised on every write), reaped like the error store; every read
  filters `expiresAt > now`, so a MongoDB without `db:setup` (no TTL index) still shows nothing expired.
- Fence `2026-11-16-person-activity-fence` (`lib/consts/migrations.ts:1901`): an older release would keep a deleted
  person's addresses and never sweep them. Its applied time is "Recording began on" (`recordingBegan`, `read.ts:39`).
- `personActivity.enabled`, on by default, reported in usage reports; off drops what is waiting. It governs the
  administrators' sign-ins too: the site promises one switch for the whole server.
- Fence `2026-11-18-admin-sign-in-log-fence` (`lib/consts/migrations.ts:1964`): an older release would silently stop
  keeping administrators' sign-ins. For the administrators' project `recordingBegan(bucketId)` (`read.ts:67`) answers
  the later of the two fences.
- No path destroys an administrator account (`admin.deactivate` keeps the row), so their rows only expire. A path that
  ever does must call `forgetPersonActivity(ADMIN_BUCKET_ID, id)`, as `removeEndUser` does for a person.

## Reading

- `POST /admin/api/projects/:id/users/:uid/activity`: a POST because the read is audited, like the network facts
  lookup. One `enduser.activity.read` per reader (an agent is its own reader), person and UTC day
  (`recordActivityRead`, `audit.ts:48`). `AUDITED_READS` (`lib/consts/admin_audit_routes.ts`) are left out of the
  audit list by `changesOnly=true`, which the person's Changes tab sends. The scheduled-deletion guard lets this POST
  through (`lib/admin/buckets/scheduled_guard.ts:16`): a project on its way out is where the activity still matters.
- The summary rides on the person's GET (`activitySummary`, `read.ts:346`): last sign-in, "not let in since", and
  "Last active" from the existing day and month marks read by id ([[monthly-active-users]]), so a token renewal
  counts. No address, country or device, so it is not audited.
- MCP: `project_user_activity_list`, `consequence: 'ordinary'`.
- **An administrator's sign-ins** (spec 137): `POST /admin/api/admins/:id/activity` (`lib/admin/users/routes.ts:327`),
  super administrators only, the same `activityPage` over the administrators' project, audited once per reader and
  day as `admin.activity.read` through `recordReadOnce`; MCP `admin_activity_list`. The project route stays closed to
  that project (`loadBucketForUsers`), so no project administrator reaches these rows. The console page is
  Administrators → Accounts → Sign-ins (`ActivityTimeline`, shared with the person's tab). `Names.client` names the
  reserved `admin-panel` and `admin-mcp` clients ("Console", "Admin MCP (reserved client)"), which carry no
  `clientName`.
- **All administrators at once** (spec 137): `POST /admin/api/admins/activity` (`lib/admin/users/routes.ts:345`,
  `activityFeed`, `read.ts:383`), MCP `admin_activity_feed`, the Administrators → Activity tab. No index of its own:
  it merges each administrator's indexed timeline (`listForPerson`, limit each) in `newestFirst` order and cuts at the
  limit, which is exact because the top N of a union lies within the union of each part's top N; the cursor is the
  last shown row. Fine for tens of accounts, wrong for a project of people. Audited once per reader and day as
  `admins.activity.read` against the administrators' project.
- **Accounts' Last sign-in**: `GET /admin/api/admins` carries `signIns` per administrator (`signInSummary`,
  `read.ts:544`, the Profile tab's first two lines shared): last sign-in and refusals since, no address, country or
  device, so the list stays unaudited and the red "Refused N times since" mark links to the audited page.
- **New sign-in emails** (spec 138): a sign-in row may carry `alerted` (`network`, `browser`, `both`), set in the
  flush before the write when its owner is emailed ([[new-sign-in-alerts]]); `words.alerted` shows it.
- **An administrator themselves**: `GET /admin/api/me/sign-ins` (`lib/admin/me.ts:59`, `ownAdminSignIns`,
  `own.ts:100`), their ten newest sign-in rows, refused ones included, built field by field without address,
  categories or lookup, so a thief holding the session learns nothing of where the real administrator signs in from;
  not audited; MCP `own_sign_in_list`; the console opens it from the email in the header.

- **The person themselves** (spec 135): Recent sign-ins on their account page reads their ten newest `signIn`
  `let_in` rows (`ownSignIns`, `lib/person_activity/own.ts:81`) through `listForPerson`, no new index. The view is
  built field by field, so the address, `addressFrom`, the network categories and any rule or tool never reach it;
  the country is shown only when it is one of `COUNTRY_CODES`. "This browser" is the row within 5 s of the session's
  `loginTs`; an unflushed sign-in has no row yet, and the page says sign-ins appear up to a minute late. Not audited:
  it is the person's own data, behind a sign-in no older than 15 minutes ([[connected-apps-page]]).

## What a person used (spec 134)

- **One row per person, place and UTC day**, `outcome: let_in`, `reason: used`: `noteAppUse` at the allowed branch of
  `lib/behind_proxy/check.ts:500` (a person and not a public path) and `noteApiUse` at `api_check.ts:278` (a token
  naming a person). Place is `{ appId }`, or `{ resource, clientId }` for an API (`record.ts:382`, `:407`). Never an
  address, network facts, a device or the rule: a day of where and how someone works is more than an administrator
  needs to see what they use (S11). `count` is the proxy's checks, which the console shows only in a tooltip: every
  image and script of a page is one (У6).
- **An API row's `tools`** is a bounded list, not part of the row's id: the names kept, then the new ones not kept, cut
  at 20 (`unionOfTools`, `lib/adapters/person_activity_rows.ts:34`). MongoDB writes such a row with an update pipeline
  (`toolsUpsertOf`, `lib/adapters/mongodb/personActivityStore.ts:61`) using only `$concatArrays`, `$filter`, `$in`,
  `$slice` and `$ifNull`, because the server connects with Stable API v1 in strict mode; every value is `$literal`,
  since a tool row name may begin with `$`. PostgreSQL computes the same list by ordinality. Names are table rows or
  `*another`, as for refusals.
- **A buffer of its own**, written every five minutes (`pendingUse`, `buffer.ts:31`; the second timer in
  `flush.ts:129`): use is almost all the volume, and the write rate, with PostgreSQL's dead row versions, scales with
  the interval (Н4). It has its own budget and per-project quota (`use`, `perProjectUse`), so a busy project's use
  never pushes out a sign-in or a refusal; over a bound it folds into the same overflow row as the other buffer.
  Deletion, the setting and the drain clear or write both.
- **An allowed check marks the person active.** `markActivityOf` (`lib/activity/note.ts:126`) shares
  `markActivity`'s per-process memo with kind `renewal`; on a miss it reads the user after the answer, unawaited, for
  `provisioned`, and skips a person no longer there. So "Last active" and monthly active people count someone working
  on an app session opened two weeks ago (owner, 2026-11-16; [[monthly-active-users]]). Not governed by
  `personActivity.enabled`, as marks never were.

## Refused recently, and Last active on the list

- **"Refused recently"** on an app's and an API's Access tab: `refusedRecently` (`lib/person_activity/refusals.ts:53`)
  reads `listRefusals` on the new `{bucketId, outcome, lastAt}` index, never the project's use rows (Н5), keeps the
  place, folds a person's rows of the two UTC days the 24 hours span, and names people by one `findMany`. Its divider
  is `accessSavedAt` on the app and the API, written only when who may get in changes (rules or time zone,
  `lib/admin/behind-proxy/service.ts:359`; tools table, sign-in requirement or checker,
  `lib/admin/resources/routes.ts:768`), because `updatedAt` moves on a rename.
- **The read is audited** like the timeline: `POST …/behind-proxy/:appId/refusals` and `…/resources/:resourceId/refusals`
  record `behindproxy.refusals.read` / `resource.refusals.read` once per reader, target and UTC day
  (`recordReadOnce`, `audit.ts:56`), both in `AUDITED_READS`; agents use `behind_proxy_app_refusal_list` and
  `resource_refusal_list`. A project scheduled for deletion is read like any other.
- **"Last active" on the list of people** is a column and a filter, never a sort (У1). The column reads the page's
  marks in one query (`lastMarkedMany`, on the new `activityMarks` index `{bucketId, accountId, period}`); the filter
  is `EndUserFilter.lastActive`, applied as `EXISTS`/`NOT EXISTS` on PostgreSQL and as an id set from
  `accountsMarkedIn` on MongoDB and memory, like `memberOf`. "Not in the last 90 days" is read from month marks, and a
  month overlapping the window counts as active (`lastActivePeriods`, `lib/adapters/activity_records.ts:139`).
- **Profile's "Apps used in the last 90 days"** folds the person's use rows by place (`appsUsedBy`, `read.ts:349`).
