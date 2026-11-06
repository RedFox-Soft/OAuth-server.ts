---
type: concept
title: 'Conditions at your proxy: network, hours, attribute, fresh sign-in'
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-06
updated: 2026-11-06
---

# Conditions at your proxy

Spec 124. A path of an app behind the proxy ([[behind-your-proxy]]) and an API whose tokens the proxy checks
([[token-checks-at-your-proxy]]) can carry conditions on top of "who": **network** (`only`/`not` ranges),
**time** (windows in one IANA zone), **attribute** (an administrator- or SCIM-set field), **fresh** (apps: sign-in no
older than N minutes) and **group** (APIs). A condition only narrows; kinds combine with AND, values inside one kind
with OR; at most one condition of a kind per rule (`lib/admin/conditions.ts` `conditionsFrom`).

## One pure decision, fed the address it may believe

`decide()` still decides alone, for the check and the console (`lib/behind_proxy/decide.ts`), and imports only pure
siblings: `net.ts` (strict address parsing, ranges, membership via `BigInt`), `clock.ts` (minute of the week in a
zone through a cached `Intl.DateTimeFormat`), `conditions.ts` and `condition_widening.ts`. The console bundles all
four. Property tests compare `net.ts` with `node:net` `BlockList` and `clock.ts` with a calendar reference
(`test/behind_proxy/conditions_properties.spec.ts`).

**Conditions accumulate down the path tree** (`gatherConditions`): "who" is still the longest rule's, but every
covering non-public rule adds its conditions. A child cannot drop a parent's condition, which an earlier draft
allowed silently.

**Fixed order** (research R2): network and time before any session (no password asked before a refusal by place or
hour); then session, `canSignIn`, groups; then attribute; then fresh sign-in last, so nobody signs in only to be
refused. `explain: true` is the console's "Check access": an input not given is `unknown` instead of `fail`.

## The person's address: key plus overwrite, never the caller

`believedAddress` (`lib/behind_proxy/believed_address.ts`): the address comes from `X-Forwarded-For` only when the
check carries `X-FoxAuth-Proxy-Key` matching a digest in `UserBucket.proxyKeys`, and the header holds exactly one
strictly parsed address. Every spec 122/123 recipe passes the browser's own headers to the check (Traefik copies all
client headers when `authRequestHeaders` is empty; nginx and Caddy forward them), so the key's job is to prove the
proxy runs the new recipe, in which the same block overwrites `X-Forwarded-For` with the connection address.

- An unknown address fails every network condition, `not` included. A non-public address (private, loopback,
  link-local, CGNAT) is unknown for `not` unless the condition names it: behind a load balancer "not from Tor" would
  otherwise admit everyone.
- The address is never `callerAddressOf`, a rate-limit key, an attack report, a log line or an event field. See
  [[caller-address]].
- Saving a network condition needs `addressProvenAt` (a keyed check from one public, non-Cloudflare, non-probe
  address) later than `addressForgedAt` (the console's probe `192.0.2.66` reached the check): 409
  `proxy_address_unproven`. One save cannot lock everyone out or trust a browser-chosen value.
- Keys: at most two per project, SHA-256 digests, never in any view; issuing is console-only (it answers the key),
  listing and withdrawing are MCP tools (`lib/admin/buckets/proxy_keys.ts`). Checks read keys only when one is
  presented, cached 30 s (`proxy_key.ts`).
- Traefik cannot add a header to its forward-auth request, so its key rides two `headers` middlewares (one adds it
  before `forwardAuth`, one clears it after). A real Caddy 2, nginx 1.27 and Traefik v3 run on 2026-11-06 proved, for
  all three, that a forged `X-Forwarded-For` never reaches the check and the key never reaches the app
  (`ADDRESSES_SUPPORTED`, `recipes.ts`); a proxy added later starts unsupported until a run proves
  the key never reaches the app.

## API: who stands behind a token

`Presented.accountId` (`bearer.ts`) is the person, never derived from `subject`: an opaque `AccessToken`'s
`accountId`; a `ClientCredentials` token is nobody; a JWT is a person only if it carries `auth_time`, its client is not
pairwise and `sub !== client_id`. Access tokens therefore carry `authTime`/`acr`/`amr` (JWT `auth_time`/`acr`/`amr`,
RFC 9068 §2.2.1) from the four grants with an interactive sign-in; a refresh copies the original. The API check reads
the person in the API's project, applies `canSignIn` uncached (an API has no session record a lock removes) and caches
only groups and attributes for 60 s (`api_person.ts`). API conditions live in `tools.access` of the closed
`ToolsTable`.

## Fresh sign-in

The app session records `authTime`/`acr`/`amr` from the redeemed code. A stale sign-in is `sign_in` with
`maxAgeSeconds`; `/_foxauth/start` passes `max_age`; the pending sign-in remembers it and the callback refuses a code
whose `authTime` is older (60 s skew) with "We couldn't confirm your sign-in", never a loop; the replaced session is
deleted. The federated start forwards `prompt=login` and `max_age` to the provider (`freshSignInParams`,
`lib/interactions/index.ts`); the provider's own `auth_time` is not checked.

## Attributes a person cannot set

Selectable: the enterprise profile fields, `title` and `claim:<key>`, except the claims federation copies in and the
server's own (`NOT_SELECTABLE_CLAIMS`, `conditions.ts`). A condition nobody in the project matches is refused (409
`attribute_matches_nobody`, counted by `EndUserFilter.attribute` on all three stores).

## Widening is structural

`widenings()` probes paths for "who" as before and, per probe path, compares the gathered conditions kind by kind
(`condition_widening.ts`): ranges by coverage, windows by a 10 080-minute bitmap (a zone change always widens), values
by subset, `maxAgeMinutes` by order. Sound, not exact: it may ask once too often, never too rarely (property test C28).

## Rollback fails closed

A rule with conditions is stored as `who: { kind: 'conditional', who, conditions }`, which an older schema refuses
(500, not ignored); API conditions are a field of the closed `ToolsTable`. The no-op migration
`2026-11-06-proxy-conditions-fence` makes an older release refuse to start and its `db:migrate` exit 1. Cost: no
rollback below this release, and during a rolling deploy older processes answer errors for conditioned apps and APIs.

## Related

- [[behind-your-proxy]], [[token-checks-at-your-proxy]] — the checks these conditions narrow.
- [[caller-address]] — why the proxy's address is still never the caller.
- [[admin-mcp-control-plane]] — `highWhenSets` now includes `timeZone`; the issue route is withheld.
