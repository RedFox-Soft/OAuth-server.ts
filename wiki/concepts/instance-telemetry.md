---
type: concept
title: 'Instance telemetry: the daily usage report'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-10-28
updated: 2026-10-28
---

# Instance telemetry: the daily usage report

Every FoxAuth instance with a datastore sends one anonymous report per UTC day to FoxTrust (spec 113). The report
holds the version, runtime, storage backend, which feature settings are on, coarse ranges of the instance's size, and
the previous day's token and defect figures. FoxTrust receives it (FoxTrust spec 034) at a permanent URL,
`TELEMETRY_DESTINATION` (`lib/consts/telemetry_fields.ts:16`). The maintainers use it to decide what to keep, fix and
retire, which they otherwise did blind.

## The owner's decisions (2026-10-28)

- **On by default, and the setting is the only switch.** `telemetry.enabled` defaults to `true`
  (`lib/configs/application.ts`, beside the `sentry.*` block). The reasoning: a report carries no personal data,
  and an operator sees exactly what is sent. **No environment variable** turns it off: `FOXAUTH_TELEMETRY` and
  `DO_NOT_TRACK` were built and removed the same day by the owner, because a setting lives where an operator and an
  agent can see and change it. For the same reason the container guess reads only marker files, never
  `KUBERNETES_SERVICE_HOST`.
- **A report that cannot be delivered is not an error.**
  - `sendReport` (`lib/telemetry/send.ts:14`) returns `false` for everything that is not a 2xx and logs nothing.
  - It does not follow redirects (`:28`).
  - `reportPass` (`lib/telemetry/scheduler.ts:25`) swallows every failure.
  - Nothing reaches the error store.

  The point is that an air-gapped server looks exactly like one that reported.
- **A random identifier.** The identifier is a UUID created by insert-if-absent in a singleton document in
  `serviceConfig`, derived from nothing (`lib/adapters/types.ts`, `TelemetryState`). A database copied to a second
  server keeps it, and that limitation was accepted.
- **No destination override.** A `FOXAUTH_TELEMETRY_URL` was proposed and dropped:
  - tests do not need it, because the fetch mock intercepts any URL;
  - a private receiver is a feature nobody asked for.

  A manual check against another receiver uses `scripts/telemetry_report_now.ts --to`. That is an argument of the
  script, not configuration of the server.

## How one report a day survives several processes

- **The claim.** A pass atomically claims the day (`claimDay`, `lib/telemetry/scheduler.ts:38`). The store contract
  requires one conditional statement, never read-then-write, the same rule as the migration lease. A claimed day is
  never released, so a failed send is not retried and a missed day is never sent later.
- **The slot.** Each instance reports at a minute derived from its identifier (`slotOf`, `lib/telemetry/slot.ts:8`).
  All processes of an instance agree on it, and instances spread across the day.
- **The timer.** It runs every 15 minutes, unreferenced, and is started from `lib/index.ts:315` only when a
  datastore is configured. An in-memory instance would get a new identifier at every start. The pass itself does
  **not** check the backend (`reportingAllowed`, `lib/telemetry/status.ts:19`), so that the in-memory test suite can
  run passes. `reportingState` (`:31`) adds `no-datastore` for the console.

## Day figures

- **Tokens.** `noteTokens` (`lib/telemetry/counters.ts:35`) is called beside `noteActivity` in `executeGrant`
  (`lib/actions/grants/index.ts:138`). Grants are counted under short names from `GRANT_SHORT_NAMES`.
- **Defects.** `noteServerError` (`:42`) is the first statement of `captureFault` (`lib/error_store/capture.ts:65`),
  **before** the `errorStore.enabled` check. The count must not depend on whether the store is on. Callers gate on
  a 5xx, but some record background work, so the field counts defects, not responses.
- **Counting.** Both functions count in process memory. `flushCounts` (`:59`) adds the counts to the shared state on
  every pass and keeps three days. One write per process per quarter-hour replaces one per token. A crash loses at
  most a quarter-hour, which a range does not show.

## What may be sent, and the guards

`lib/consts/telemetry_fields.ts` is the single declaration of every field. The builder, the console card and the site
page (`/docs/reference/telemetry/`, via the docs export) all read it.

- **Settings.** Every boolean setting is in `REPORTED_SETTINGS` (`:58`) or in `UNREPORTED_SETTINGS` (`:111`) with a
  reason. `test/telemetry/declaration.spec.ts` fails on one that is in neither. **A new boolean setting must be
  classified in the same change.**
- **Receiver rules.** FoxTrust refuses with 422 and loses a report that breaks its validator, so the declaration is
  held to the receiver's rules: the key shape (`:235`), at most 100 features and 32 grant names, and a report at its
  largest under 4 KB.
- **Size.** `size` must carry all five figures. If one cannot be read, `buildReport`
  (`lib/telemetry/report.ts:144`) returns `null` and nothing is sent that day.
- **The last report.** It is stored as the **JSON text sent** (`lib/adapters/types.ts:675`), not as a document,
  because a jsonb column reorders keys. `database/verify_telemetry.ts` found this on PostgreSQL. The console promises
  the report exactly as it left.

## Surfaces

- `GET /admin/api/settings/telemetry`, super administrators only, and the MCP tool `telemetry_status_get`. The route
  is mounted as a statement of its own (`lib/admin/routes.ts:138`), because the chained admin route set is at
  TypeScript's instantiation limit (TS2589).
- The console card `lib/admin/ui/settings/TelemetryCard.tsx` sits on the Integrations pane. It never shows a missed
  delivery in error styling.

## Not the same as

- **The error store and Sentry.** Those report faults to the operator, opt-in. This report goes to the maintainers,
  on by default, and carries counts only.
- **Monthly active users.** That figure is per project, for the operator ([[monthly-active-users]]). The report sums
  it into one range.
