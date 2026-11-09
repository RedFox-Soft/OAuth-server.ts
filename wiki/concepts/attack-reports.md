---
type: concept
title: 'Attack reports: the addresses that attacked an instance, hourly, to FoxTrust'
tags: [architecture, security, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-10-29
updated: 2026-11-09
---

# Attack reports: the addresses that attacked an instance, hourly, to FoxTrust

Every FoxAuth instance with a datastore tells FoxTrust which public addresses attacked it in the hour before
(spec 114). FoxTrust combines the reports of many instances into a first-party feed of attacking addresses.
It is the second half of [[instance-telemetry]] and shares its destination host, instance identifier, sender
and state document. Who a request came from is [[caller-address]].

## The owner's decisions (2026-10-28)

- **From every installed instance, on by default.** The legal basis is the legitimate interest in network and
  information security (GDPR Recital 49), so no consent. The operator must still be told: a startup line, a
  console card that shows the exact last report, and a public page an operator can cite
  (`website/src/pages/docs/reference/attack-reports.astro`).
- **A setting of its own, `attackReports.enabled`, and no environment variable.** It is independent of
  `telemetry.enabled`, so an operator can keep the anonymous usage report and stop sending addresses.
- **Silent failure, as for usage reports.** An undelivered report is discarded: no retry, no log line, no
  error-store record.

## Where each attack is counted

One synchronous call, `noteAttack(request, type, probe?)` (`lib/attack_reports/tally.ts:65`), beside a refusal
the server already makes. One refusal is deliberately not counted (spec 125, 2026-11-09): a password sign-in refused
because of FoxTrust's attacker list, which would otherwise let people refused by mistake keep their own address
listed ([[shared-attacker-list]]):

| Type | Threshold | Site |
| --- | --- | --- |
| `signin_failures` | 10 | the login POST's two throttle refusals, unknown account and wrong password (`lib/interactions/index.ts:1269-1302`), and the TOTP verify POST's two refusals (`:1442`, `:1466`) |
| `client_auth_failures` | 10 | the two callers of `tokenAuth`: `lib/plugins/auth.ts:69` and `lib/actions/authorization/device.ts:117`, through `noteClientAuthFailure` (`tally.ts:151`) |
| `admin_credential_failures` | 5 | `lib/scim/index.ts:122` and `lib/mcp/index.ts:269` |
| `mail_requests` | 10 | the first statement of `admitMailRequest` (`lib/mail_limit/tally.ts:37`) |
| `flood` | 20 | the per-origin rate limit's refusal (`lib/plugins/rateLimit.ts:187`) |
| `probe` | 1 | the first `onRequest` (`lib/plugins/instancePlane.ts:94`), after the caller address is settled |

What deliberately does not count:

- **A request that presented no credential.** A public client sending only `client_id`, an MCP client's first
  request without a token, a SCIM request without `Authorization`. `noteClientAuthFailure` decides by what the
  request carried, not by the error's wording. It detects a client certificate by its header, not by parsing
  it, because reading an untrusted certificate header warns the operator, and an attacker must not be able to
  write log lines.
- **A sign-in refused after the password was right** (a deactivated or unverified account): nothing was
  guessed.
- **An MCP failure reported as `unknown`**: a fault, not a refused credential.
- **The failed-credential charge of global token revocation and back-channel logout**: upstream identity
  providers, outside the closed list.

**Why not the event bus.** `login_throttled` carries no address on purpose (`lib/interactions/index.ts:1265`),
wrong passwords emit nothing, and putting the address on a channel deployments log would break the sign-in
throttle's rule. The only way an address leaves the process is an attack report.

## The tally

- **In memory, per process, per UTC hour.** A datastore write per attacking request is the amplifier
  [[per-origin-rate-limiting]] was designed to avoid. Thresholds therefore apply per process, and the receiver
  sums reports by instance and hour.
- **A hard cap, not an LRU.** At most `ATTACK_MAX_TRACKED_ADDRESSES` (10 000) addresses per hour. Once reached,
  new addresses are ignored and known ones keep counting. Under an address-rotation flood an LRU would evict the
  heaviest early hitter, the address most worth reporting.
- **The address is reduced before it is stored** (`lib/attack_reports/address.ts:35`): unattributed and
  non-public addresses are dropped through `isPublicAddress`, IPv4-mapped IPv6 becomes IPv4, and IPv6 becomes
  its /64. An attacker rotating within its /64 is one entry.

**IPv4-mapped is the trap.** Bun reports every IPv4 connection on a dual-stack socket as `::ffff:a.b.c.d`.
Without the conversion every IPv4 attacker would be reported as the /64 of `::ffff:0:0`.

## Sending

`attackReportPass` (`lib/attack_reports/scheduler.ts:43`), on a five-minute unreferenced timer started in
`lib/index.ts` under the same guards as the usage report (not under test, not on the in-memory backend):

- **The minute.** The previous hour is sent `slotOf(instanceId) % 25` minutes past the hour (`SPREAD_MINUTES`,
  `:25`). From minute 30 it is dropped unsent (FR-010).
- **Once per hour per process.** `lastHandledHour` (`:32`) only moves forward, so a clock that jumps back
  sends nothing twice.
- **No claim in the datastore.** Each process reports what it saw. Unlike the usage report's daily claim, a
  claim here would make one process's report hide another's addresses.
- **The report** (`lib/attack_reports/report.ts:40`). Only types at or above their threshold; only addresses
  left with one; heaviest first, at most 500; trimmed under 64 KiB; `omitted` says how many did not fit.
  `addressSource` is the operator's `clientAddress.source`, so the receiver knows whether an address can have
  come from a forwarded header.
- **The sender is the usage report's** (`lib/telemetry/send.ts`), with the attack destination.

## What the operator sees

The last report and the last delivery are two optional fields of the usage-reporting state document,
`lastAttackReport` (text, for the reason `lastReport` is text) and `lastAttackDeliveredAt`, written by
`recordAttackSend`. A console request may land on any process, so it has to be the datastore. No migration:
both fields are optional members of a JSON document.

`GET /admin/api/settings/attack-reports` (super administrators only, because it names addresses) feeds
`lib/admin/ui/settings/AttackReportsCard.tsx` and the MCP tool `attack_reports_status_get`. The card's two tables
come from the declaration, so the console explains exactly what can leave.

## One declaration

`lib/consts/attack_report_fields.ts` holds the destination, format, types and thresholds, probe paths,
fields, bounds, the receiver's retention and the console's example. The counting, the report, the card, the
docs export and the site page all read it. `test/attack_reports/declaration.spec.ts` builds a report with
every type and label and fails on a field, type or label the declaration does not list. A change to a type's
meaning or threshold, to a field, or to the address form is a new `format`. A new probe label is not, but each
must be a file of another product: `test/attack_reports/honest_visitors.spec.ts` checks that the server
answers 404 for every probe path.

## Bound on the receiver

FoxTrust must never list an address on one instance's reports alone: reports are unauthenticated, and a
`clientAddress.source` that does not match the deployment lets an attacker choose the address an instance
reports. The retention quoted on the public page (`ATTACK_REPORT_RETENTION`) must match the FoxTrust receiving
spec before the first release that sends.

The conformance instance turns `attackReports.enabled` off: the conformance suite attacks it on purpose.
