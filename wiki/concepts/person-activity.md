---
type: concept
title: "A person's activity: sign-ins and what the proxy refused"
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-16
updated: 2026-11-16
---

# A person's activity: sign-ins and what the proxy refused

Spec 133 ("5A" of the visit log). What this server **decided** about a person, kept per person for 90 days and shown on
the person's Activity tab: every sign-in, every failed sign-in where the account was already found, every stop on the
sign-in path, and every "Asked to sign in again" and "Refused" of an app behind the proxy or an API checked at it.
Requests let in at the proxy are not recorded (that is 5B). The module is `lib/person_activity/`; the area is
`personActivity`.

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
- **Notes never touch the datastore.** Every `note*` is a synchronous `Map` operation that never throws
  (`buffer.ts:63`), so the password door costs a found and a missing account the same reads (tested).
- **The administrators' project is never recorded** (`recording`, `record.ts:49`, and again at the flush).

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
- `personActivity.enabled`, on by default, reported in usage reports; off drops what is waiting.

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
