---
type: concept
title: "FoxTrust's network facts in \"From where\" at the proxy"
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-11
updated: 2026-11-12
---

# FoxTrust's network facts in "From where" at the proxy

Spec 129. A super administrator turns on `networkFacts.enabled` (Settings → Integrations, off by default, no
environment variable). Each process then downloads FoxTrust's ordinary signed snapshot, the same file every FoxTrust
customer gets, and "From where" in the conditions of an app behind the proxy or an API checked at the proxy can keep
out Tor, commercial VPNs, hosting or clouds, and allow or keep out countries. The modules are `lib/network_facts/`
and the transport shared with the attacker list, `lib/foxtrust/`.

## Why the snapshot, and not FoxTrust's API

The owner chose (2026-11-11) that the address of a person is only ever looked up inside FoxAuth: no per-request call,
no `/verify` beside the proxy. Since spec 133 (2026-11-16) the same local lookup also gives a person's activity the
country and categories of a recorded sign-in address or proven proxy address, and nothing else ([[person-activity]]). FoxTrust's API answers from the same snapshot loader, so it is not fresher. FoxTrust's
spec 040 moved AS data, region and city out of the published files (13.2 MB full after it), so the ordinary snapshot
is small enough to download as it is; nothing is built for FoxAuth. AS number and organisation, region and city came
in spec 136 (2026-11-17), not on an administrator's action as planned here but by default, at the activity flush,
through FoxTrust's API with a key the instance registers for itself ([[address-lookup]]). That is the one place a
person's address leaves the server; a condition still never sends one.

## The download: each process its own, only the build time shared

- `networkFactsPass` (`lib/network_facts/fetch.ts`) follows FoxTrust's own consumer (FT `src/verify/loader.ts`):
  signed manifest (conditional, `If-None-Match`) → full file, if its version is new → the hourly update only when its
  `base` is that full file → size from the manifest, sha256, detached Ed25519 signature with the pinned keys
  (`lib/consts/foxtrust_publication.ts`, shared with the attacker list) → `database_type` `FoxTrust-Customer-Verdict`,
  MMDB 2.0, IPv6 tree.
- A file is read into a buffer of the manifest's size, refused unread above 40 MB (full) or 20 MB (update), so the
  old and new pair side by side stay inside the spec's 60 MB.
- The pair's build time is the later of the two; `TelemetryState.networkFactsBuiltAt` is raised atomically before the
  pair is used, so an older signed pair is refused after a restart too.
- The swap is one reference assignment (`acceptPair`, `lib/network_facts/state.ts`).
- A look every 5 minutes plus a per-process offset under a minute (`lib/network_facts/scheduler.ts`), so an hourly
  update is in use within 10 minutes; an unchanged manifest is one `304`.

## Fails CLOSED, the opposite of the attacker list

The attacker list refuses people, so missing data refuses nobody. A network facts condition lets people in, so data
that is off, not loaded, more than 26 hours old (FoxTrust's own limit) or unreadable for an address is
`{ known: false }`, and every condition on it fails, whatever its outcome. The proxy answers
`X-Auth-Reason: network_facts_unknown` and a page that says the page cannot be opened right now. The console marks
every such path (`networkFactsClosed`, `lib/admin/ui/pages/behind-proxy/appView.ts`).

## The reader is narrow and never throws

`lib/network_facts/mmdb.ts` reads the tree (24/28/32-bit records) and only the data types these records use; every
read is bounds-checked and pointers are followed to depth 8. A record of another shape is unreadable, which makes that
one address unknown and is counted on the card (FR-008), never an exception on a person's request. The update is
looked at first; `{ removed: true }` means no record; no data means the full file decides
(`lib/network_facts/facts.ts`). Only `categories` (tor, vpn, hosting, cloud → hosting) and `country.iso_code` are read;
never `risk`, `level` or `reasons`: refusing on a verdict alone is the GDPR Art. 22 line the research drew.

## The condition

- An optional `facts` on the network condition, not a new kind: a rule keeps at most four conditions, and a changed
  network condition already meets the 409 `proxy_address_unproven` guard; with `facts` the ranges may be empty.
- `factsVerdict` (`lib/behind_proxy/conditions.ts`): missing (no believed address), unknown, match or clear. An
  address with no record has no category and no country: "Only from" countries match it, "Not from" do not. For an
  address of the proxy's own network that differs on purpose from the ranges, where "Not from" refuses it.
- Refuse is decided with the ranges, before any session. "Sign in again within N" (apps only) joins the fresh
  conditions (`freshOf`, `lib/behind_proxy/decide.ts`), so specs 124/128's sign-in, callback check and code pages are
  reused unchanged, and turning its code on is previewed as a fresh condition's is.
- Adding or changing `facts` while the download is off is 409 `network_facts_off`; a saved one stays.
- The decision receives the facts, never the snapshot (`factsForBelieved`, `lib/network_facts/lookup.ts`), and only
  for the address the check believed.
- Check access cannot hold the snapshot: it asks `POST /admin/api/network-facts/lookup` (any administrator; the
  address in the body, never a URL; audited as `networkfacts.lookup` without the address) and hands the answer to the
  same `decide()`.
- A fence migration (`2026-11-13-proxy-network-facts-fence`) keeps older releases off a database that may hold one.

## Measurements

Taken on 2026-11-12 with FoxAuth's own pass and reader against the live publication, after FoxTrust 040 was deployed
(full `f20261112`, 13.19 MB, 2,125,085 ranges; update `d20261112T05`, 1.73 MB):

- First load, both files: 2.5 s.
- Process memory (RSS): +24.5 MB with one pair held, +43.3 MB with the old and new pair side by side during a
  replacement, inside the spec's 60 MB.
- Lookup: 0.72 µs for IPv4 and 1.15 µs for IPv6, with no memory growth across 120,000 lookups. The first version
  walked the tree with a bigint shift per bit, 128 allocations per IPv6 lookup: 4-5 µs and the heap high-water up by
  about 90 MB. The reader now reads the address as 32-bit words once (`lookup`, `lib/network_facts/mmdb.ts`).
- Traffic per process, a normal day: one full file (13.2 MB) and 23 cumulative updates, each a little larger than the
  last. Before 040 an update grew from 2.0 to 3.3 MB over a day against a 24.4 MB full file; after it the first of the
  day was 1.7 MB, so a day is about 60 MB. The updates are cumulative by FoxTrust's design: a missed one costs
  nothing, at the price of downloading the day's changes again every hour.
- A change of FoxTrust's record format rewrites every record: the updates of 2026-11-11 from 23:00, made against the
  pre-040 full file, were 13.2 MB each until the next full file. The 20 MB cap on an update leaves room for that.
