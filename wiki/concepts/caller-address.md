---
type: concept
title: 'The caller address and the per-caller mail limit'
tags: [architecture, security, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-10-28
updated: 2026-11-09
---

# The caller address and the per-caller mail limit

Every address-based decision attributes a request to one address: the [[per-origin-rate-limiting]], the
failed-credential charges at SCIM and the upstream signals, the error store's recorded origin, and the mail
limit. Spec 115 made that one function, `callerAddressOf` (`lib/helpers/caller_address.ts:170`), because the
old answer could be chosen by the caller.

Since spec 122 (2026-11-05) one caller narrows its answer. The check a proxy makes for an app behind it is
always called by the proxy, and a trusted proxy's `X-Forwarded-For` names the person it is asking about. So
`checkCallerOf` replaces an address resolved from that header with the connection it arrived on
(`lib/behind_proxy/rate_limit.ts:59-70`; [[behind-your-proxy]]).

Since spec 125 (2026-11-09) the password door also asks FoxTrust's attacker list about the caller's address. It never
asks about a trusted proxy's, a Cloudflare edge's, an unattributed or a non-public address (`listedCandidate`,
`lib/attacker_list/at_sign_in.ts`), so a server whose address source is wrong refuses nobody rather than everybody
([[shared-attacker-list]]).

## The defect it replaced

Until spec 115 the rate limiter read the address itself (`originOf` in `lib/plugins/rateLimit.ts`). Whenever
the boolean `rateLimit.trustedProxy` was on, which was the default, it took the first value it found among:

1. `Fly-Client-IP`;
2. the **first** entry of `X-Forwarded-For`;
3. `X-Real-IP`.

The error store read the first entry of `X-Forwarded-For` on its own, whatever the setting said.

- **Directly exposed.** A caller sent a new `X-Forwarded-For` with every request and was never limited.
- **Behind nginx, Caddy, Traefik, a cloud load balancer or Cloudflare.** The address was still forgeable:
  - these proxies pass a caller's `Fly-Client-IP` through untouched, and it was read first;
  - they **append** the real address to `X-Forwarded-For`, and the leftmost entry is whatever the caller
    sent.
- **The setting off.** Every caller became the proxy, so the whole internet shared one allowance and was
  refused within seconds.

On most deployments there was no correct value. Only Fly.io was safe, because Fly's edge overwrites
`Fly-Client-IP`. The owner found it while specifying [[instance-telemetry]]'s attack reports (spec 114),
which must not report an address an attacker chose.

## What Fly.io actually sends (probed 2026-10-28)

The facts came from a throwaway echo app on Fly, destroyed afterwards, hit with forged headers:

| What | Seen |
| --- | --- |
| Connection (socket peer) | `::ffff:172.16.x.x`, a private IPv4 address in IPv6-mapped form |
| `Fly-Client-IP` forged as `1.2.3.4` | **overwritten** with the real client |
| `X-Forwarded-For` forged as `9.9.9.9, 8.8.8.8` | `9.9.9.9, 8.8.8.8, <client>, 66.241.125.11`: the caller's entries are kept, and the **rightmost entry is the app's own shared IPv4** |
| `X-Real-IP`, `CF-Connecting-IP`, `Forwarded` | passed through unchanged |

Two consequences:

- **A generic right-to-left walk fails on Fly.** It would stop at the app's own address and attribute every
  caller to it. That is why "fly" is a choice of its own and reads `Fly-Client-IP`.
- **A peer check must parse addresses.** It has to recognise IPv4-mapped IPv6, or Fly's proxy is never seen
  as private.

## The rule now

`clientAddress.source` (`lib/configs/application.ts:599`) names how the server is reached. A forwarded
header is believed only on a connection from a proxy the choice trusts (`isTrustedProxy`,
`lib/helpers/caller_address.ts:56`).

| Choice | Trusted connections | Header read |
| --- | --- | --- |
| `automatic` (default on a new install) | private networks: RFC 1918, loopback, link-local, unique-local | `X-Forwarded-For`, walked |
| `direct` | none | none |
| `fly` | private networks | `Fly-Client-IP` |
| `cloudflare` | private networks and Cloudflare's published ranges (`lib/consts/cloudflare_ranges.ts`) | `X-Forwarded-For`, walked |
| `listed` | private networks and `clientAddress.trustedProxies` | `X-Forwarded-For`, walked |

- **The walk** (`walkForwardedFor`, `:98`).
  - Read right to left, skipping each entry a trusted proxy wrote. The first untrusted entry is the caller.
  - If every entry is trusted, take the rightmost, so a client inside the operator's own network cannot
    rotate forged private entries.
  - A non-address entry stops the walk at the last trusted hop. Header text never becomes the caller.
- **Shared address space is not a proxy network.** `100.64.0.0/10` (carrier-grade NAT, Tailscale) is
  deliberately left out (`isProxyNetworkAddress`, `lib/helpers/public_address.ts:155`). A client there is the
  caller and cannot forge a header. This was found in the analysis of spec 115.
- **Cloudflare is the walk, not `CF-Connecting-IP`.** Cloudflare appends the visitor to `X-Forwarded-For`.
  Reading that also works for Cloudflare in front of nginx, where the peer is nginx and a peer check on
  Cloudflare's own header would fail.
- **The classifier is shared.** `isPublicAddress` (`lib/helpers/public_address.ts:124`) moved out of
  `lib/shared/egress.ts`, which now calls it. [[attack-reports]] (spec 114) uses the same predicate to decide
  which addresses may be reported.

## The proxy check's person address (spec 124)

The check for an app or an API behind the operator's proxy still treats the proxy as its caller
(`checkCallerOf`, `lib/behind_proxy/rate_limit.ts`). Spec 124 adds a second, separate address: the **person's**,
read from `X-Forwarded-For` only when the check carries a valid project proxy key and the header holds exactly one
strict address (`believedAddress`). That address is only compared with a network condition's ranges. It never becomes
`callerAddressOf`, a rate-limit key, an attack report, a log line or an event field. See [[conditions-at-your-proxy]].

## One answer per request, without `server`

- **Where it is computed.** The first statement of the first `onRequest` hook
  (`lib/plugins/instancePlane.ts:80`) computes the address while the socket is in hand.
  `callerAddressOf` keeps the result in a `WeakMap` keyed by the `Request`, so an error handler or a mail
  route reads the same answer with no `server`.
- **Why not a plugin of its own.** A separate plugin pushed the app chain in `lib/index.ts` past TS2589.
  That is the reason `oversizeBodyRefusal` already gave for living there.
- **The MCP dispatch path.** It rebuilds requests in process, so they have no connection. They are
  `unattributed`, as before, and the rate limit keeps counting them together.
- **Tests.** `elysia.handle()` has no socket, so specs state the peer through `setPeerResolverForTests`
  (`:128`); `test/caller_address/helper.ts` passes it in a header only that resolver reads.

## The upgrade

Migration `2026-10-29-client-address-source` (`lib/consts/migrations.ts:1620`) carries every instance off
the boolean without a manual step:

- `false` becomes `direct`;
- an instance with an administrator becomes `fly`, which is exactly the old default's correct behaviour on
  the shipped deployment and no worse anywhere else;
- a fresh database, which has no administrator yet, keeps the code default `automatic`.

It creates the settings document when an operator never saved one. In the MongoDB step it imports the
driver dynamically to build the document's `ObjectId`, so the module stays importable without a driver.
`database/verify_client_address.ts` runs it on both real backends.

The console card `lib/admin/ui/settings/CallerAddressCard.tsx` shows the operator what the server attributes
to their own request. It warns when the choice contradicts that request (`warningFor`,
`lib/admin/settings/client_address/routes.ts:36`): "fly" without a Fly header, a Fly header under another
choice, or proxy headers on an untrusted connection. A non-Fly instance carried to `fly` is caught there.
The route is excluded from MCP, because a dispatched call has no connection to describe.

## The per-caller mail limit

Each recipient already had its own limits: a cooldown and a daily cap for password reset, and the same for
verification. Nothing limited how many different recipients one caller could name. The only bound was the
strict rate class, 60 a minute, shared with sign-in.

- **What counts.** `admitMailRequest` (`lib/mail_limit/tally.ts:32`) is called first in four routes:
  - forgot-password (`lib/interactions/index.ts:1832`);
  - registration (`:1922`, before the account exists);
  - the interaction verification resend (`:1784`);
  - the standalone resend (`lib/routes/verification.ts:89`).
- **How it counts.** It counts every request, whatever its outcome, so a refusal cannot reveal which
  addresses have accounts. [[self-service-password-reset]] removed a rate-limited page for exactly that
  leak.
- **Where.** In the datastore, area `MailRequestTally`, one record per caller and UTC hour, using
  insert-if-absent and then an atomic increment, then a compare. The limit holds across processes and under
  a parallel burst. Unlike the rate limit's in-memory counters, this costs no amplifier: these routes already
  write.
- **The limit.** `mail.requestsPerCallerPerHour`, 10 by default, is a console setting.
- **What is not counted.**
  - Requests with no address: none reach these routes in a running server, and counting them together would
    make every in-process test share one tally.
  - Mail an administrator sends.
- **The refusal.** A 429 with `Retry-After` and the form the visitor was on. The interaction resend
  redirects with the `mail_limited` notice instead, because a login document served at its own path never
  hydrates.
