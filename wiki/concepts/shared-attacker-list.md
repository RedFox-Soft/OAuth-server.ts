---
type: concept
title: "FoxTrust's attacker list at password sign-in"
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-09
updated: 2026-11-09
---

# FoxTrust's attacker list at password sign-in

Spec 125. FoxTrust publishes, every hour, a signed list of the addresses it saw guessing passwords in the last 7
days (its spec 037; contract public at https://foxtrust.dev/docs/snapshots, "Attacker list"). FoxAuth downloads it
and each project decides what a password sign-in from a listed address meets: nothing, counting only (the default),
or refusal (`UserBucket.passwordGuessing`). The module is `lib/attacker_list/`.

## The list: each process its own, only the build time shared

- `attackerListPass` (`lib/attacker_list/fetch.ts`) follows FoxTrust's verification order: signed manifest →
  `attackers["1"]` → file and detached Ed25519 signature → size and sha256 → header (`kind`, `format` 1, `version`,
  `validUntil` in the future, `builtAt` later than both the held list and the stored one). The publication and the
  pinned keys are constants (`lib/consts/attacker_list.ts`), passed as defaulted arguments only so a test can sign
  with its own key; no setting or environment variable overrides them.
- No lease and no stored bytes: nothing is shared but `TelemetryState.attackerListBuiltAt`, raised atomically
  (`raiseAttackerListBuiltAt`, `$max`/`GREATEST`), written **before** the list is used, so a restart still refuses an
  older signed list. Each process keeps two sorted typed arrays (`matcher.ts`): IPv4 addresses and IPv6 /64
  prefixes, the only widths format 1 lists.
- The size cap is held on the decompressed bytes while reading: the publication is gzip through Cloudflare, so
  `Content-Length` says nothing useful.
- A signature or digest mismatch is shown only when it repeats: FoxTrust writes the manifest's signature before the
  file, so one miss around :50 is normal (`shownProblem` in `state.ts`).
- The minute tick (`scheduler.ts`) writes the counters and checks at :55 plus a per-process offset; started only off
  the in-memory backend, under the same guard as the attack report.

## Failing open is the contract

Missing, expired (`validUntil` = build + 3 h), unknown-format or unverifiable means **nobody is refused** and the
console says so. This is the opposite of [[login-door-throttle]]'s "nothing fails open": a deny list fed from one
outside server must not lock everyone out when that server goes quiet. The comment in `state.ts` says so; do not
"fix" it.

## The decision, and the owner's refusal rule

`listDecision` (`decision.ts`) is pure. Refuse needs the project to refuse, an entry seen within 48 hours, and either
FoxTrust's `corroborated` marker or three password failures from that address seen by **this process** in the last
hour (`local_failures.ts`) — the rule FoxTrust's public page states. A refusal is itself recorded and makes the
refusal sticky: refused once, an address stays refused while less than an hour passes between its attempts, so it
cannot pace itself under the threshold; an hour of quiet gives it three attempts again. The tally is separate from the
attack tally, whose clock-hour buckets are handed to the report and cannot answer "the last hour".

## Where it applies, and what it leaves alone

- Only `GET`/`POST ui/:uid/login` (`lib/interactions/index.ts`): decided after `passwordDoorClosed` and before the
  throttle, the account lookup and any verification. It never reads the account, so the refusal is identical for any
  email, and a refused attempt never reaches the per-email throttle — an attacker on the list cannot lock an owner out.
- The address is `callerAddressOf`'s; trusted proxies, Cloudflare edges, unattributed and non-public addresses are
  never looked up, so a misconfigured caller address means "nobody refused", never "everybody" ([[caller-address]]).
- A list refusal does **not** call `noteAttack` ([[attack-reports]]): a person refused by mistake would otherwise keep
  their own address listed. The three failures that led to it were already counted.
- The refusal replaces the form (`passwordLogin: false`, so provider buttons stay) and shows the person their own
  support line `listed-address · <address> · <UTC>`; nothing else records the address. The event
  `password_guessing_refused` carries the `bucketId` only.
- Federation, reset, sign-up, verification, the second-factor step and every token endpoint are untouched.

## Settings and the project

- `attackerList.enabled`, off by default, only with `attackReports.enabled` (a configuration invariant; the
  catalogue's `dependsOn` turns it off with reporting in one console save). Reported in the usage report.
- `passwordGuessing` rides the project PATCH; choosing `refuse` is a sign-in tightening previewed with the last 7 days'
  numbers (`guessingRefuseOn`, specs/083 protocol); the administrators' project refuses `refuse` with a 422.
- Counters: the model area `PasswordGuessingTally`, one record per project, day and process holding absolute totals,
  upserted once a minute, unowned and expiring after 8 days.

## Rollback

No fence: an older release ignores the bucket field, the build time and the counters, and refuses nobody.

## Related

- [[attack-reports]] — what FoxAuth sends; this is what comes back.
- [[login-door-throttle]] — the per-email throttle this sits in front of.
- [[caller-address]] — the address asked about.
- [[conditions-at-your-proxy]] — a FoxTrust condition at the proxy is later work.
