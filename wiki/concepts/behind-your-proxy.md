---
type: concept
title: 'Apps behind your proxy: sign-in in front of a web app through forward auth'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-11-05
updated: 2026-11-05
---

# Apps behind your proxy

Spec 122. A project puts sign-in in front of a web app that has none of its own (Grafana, an internal tool)
through the operator's own reverse proxy: Caddy `forward_auth`, Traefik `forwardAuth` or nginx `auth_request`.
The proxy asks the project about every request, and the project answers allow, sign in, or refuse. The app is
not an OAuth client and changes nothing. It reads who the person is from `X-Auth-*` headers.

Words: an *app behind a proxy* is a `behindProxyApps` record (`lib/consts/storage_inventory.ts:176`). The *check*
is the endpoint the proxy calls. An *app session* is a person's session at one app.

## One endpoint serves everything

`/verify/:appId` is the only route (`lib/consts/behind_proxy.ts:20-21`). It is mounted bare and beneath `/:bucket`,
like every other bucket-scoped surface (`lib/index.ts:283-284`), and with `.all`, because the method of the check
means nothing: the original method is read from `X-Forwarded-Method` (`lib/behind_proxy/routes.ts:14-18`). No body
is parsed (`parse: 'none'`). The project is chosen by the address of the check; the path names the app.

The sign-in start, the OAuth callback and the sign-out are **reserved paths on the app's own host**:
`/_foxauth/start`, `/_foxauth/callback` and `/_foxauth/sign_out`. The proxy relays them to the same check, which
answers them before any rule and never passes them to the app (`lib/behind_proxy/check.ts:155-184`). They are
recognised by the *canonical* path, so a spelling the app would read as one of them is one here too
(`check.ts:307-309`). So the callback and the session cookie both live on the app's host, and there is no second
endpoint to wire.

**nginx asks with `mode=status`.** `auth_request` understands only 2xx, 401 and 403, so the nginx recipe's internal
check adds `?mode=status`. In that mode a reserved path, a sign-in and a flood refusal are all plain statuses
(`check.ts:167`, `:350`, `:364-373`). nginx's `error_page 401 403 = @foxauth` then calls the check again without
the mode. That second call issues the redirects and pages (`lib/behind_proxy/recipes.ts:111-171`). The trailing `?`
in the relay's `rewrite` stops the browser's own query (which could say `mode=status`) from reaching the check's
address (`recipes.ts:114-116`).

Every answer carries `X-Auth-Reason` and `Cache-Control: no-store` (`lib/behind_proxy/answers.ts:20-35`). A fault
is answered 500, never 2xx, because a proxy passes the request on for any success (`check.ts:45-50`, `:375-397`).
It is recorded as the eighth capture site of [[error-store-capture-sites]].

## The forwarded host is compared, never used to select

The host-from-`Host` rule (`lib/consts/request_host.ts:133-147`, [[project-is-an-issuer]]) has **one documented
exception**, and this is it. The check reads `X-Forwarded-Host` in one place (`check.ts:285-300`). By then the
project and the app were already chosen from the check's own address and path (`check.ts:264-270`). The header can
only fail one comparison, `sameHost(forwardedHost, app.address)`, and never selects anything. `sameHost`
(`lib/behind_proxy/address.ts:62-87`) is used instead of `normaliseHost` because `normaliseHost` drops every port.
Here a port other than 443 is a different origin, and so a different app.

A missing `X-Forwarded-Host`, `X-Forwarded-Uri` or `X-Forwarded-Method` is refused as `missing_forwarded`. A
missing value is never read as `/` or `GET`, which would have the root's rule decide it (`check.ts:275-283`).

**The not-found refusals are all the same.** An unknown project, a project scheduled for deletion, an unknown app,
another project's app and a host that is not the app's address all get the same 403 `not_found`. One function
builds it, so neither status, header nor body tells a caller which ids and addresses exist (`check.ts:75-82`). The
mismatched host is remembered in memory only, for the Connect page, so the refusal stays byte-identical
(`check.ts:292-293`, `lib/behind_proxy/usage.ts:117-136`).

An app's address is canonical `https://host[:port]`. Anything else is refused at create: `http`, user info, an IP
literal (`address.ts:29-49`). One app per address per project is a unique `{bucketId, address}` index, so a route
does not have to remember the rule (`storage_inventory.ts:713-729`). The bucket name `verify` is reserved, because
a bucket of that name would lose `/verify/auth` to the check (`lib/consts/reserved_names.ts:29-30`).

## Cookies: host-only `__Host-`, and no `Domain` anywhere

Both cookies, the session `__Host-foxauth-<appId>` and the sign-in marker `__Host-foxauth-signin-<appId>`, are set
on the app's own host. One function writes their attributes for set and expiry alike: `Path=/; Secure; HttpOnly;
SameSite=Lax` (`lib/behind_proxy/session.ts:19-45`). The `__Host-` prefix makes the browser refuse a `Domain`, so a
cookie cannot be widened by mistake later. The expiry uses the same attributes because a cookie's identity includes
its path ([[cookie-path-scoping]]).

**Why there is no parent-domain cookie.** The owner decided this on 2026-11-05. A single cookie on
`.example.com` would give single sign-on across every app at once. It would also send the session to every
sibling host under that domain, including any host that is not behind the proxy, or that an attacker controls.
Pomerium dropped forward-auth in 0.21 for exactly this reason. Each app therefore has its own session, made by its
own sign-in. The project session at the issuer makes the second app's sign-in a redirect with no prompt.

## The app session is an account-owned record

The cookie holds a random 32-byte value. The record is stored under its SHA-256 and the value itself is stored
nowhere (`session.ts:62-95`, `lib/behind_proxy/payloads.ts:6-21`). A cookie of another app of the same project names
a record of that app, so it is no session here (`session.ts:102-120`). There is no sliding. The session lasts one
`ttl.Session` from the sign-in, and the cookie's `Max-Age` is the same (`session.ts:82-93`,
`lib/behind_proxy/sign_in.ts:183`).

It is a reference, not a self-contained token, so ending access is removing the record:

- `BehindProxySession` is declared **account-owned** (`storage_inventory.ts:340-348`). So `revokeAccountAccess`
  (lock, deactivation, sign-out from the console; `lib/end_users/revoke_access.ts:64-69`) and `cascadeForAccount`
  (deletion; `lib/helpers/cascade.ts:203-225`) sweep it with no code of their own, through `sweepAccountOwned`
  ([[end-user-lifecycle]], [[deletion-and-revocation]]).
- A password reset sweeps sessions only, not every account-owned area. `endSessionsForAccount` names both session
  areas (`cascade.ts:101-134`). An app session follows the person, not the project session, so a reset that left
  it would leave whoever had the old password inside the app ([[self-service-password-reset]]).
- Deleting an app ends its sessions by `appId` (`lib/admin/behind-proxy/service.ts:278-288`). Destroying a project
  ends the sessions of its apps (`lib/admin/buckets/destroy.ts:224-227`).

The pending sign-in (`BehindProxySignIn`) is unowned. It names nobody yet and expires in ten minutes
(`storage_inventory.ts:349-359`). Its PKCE verifier and marker digest are declared plaintext in
`lib/consts/sealed_fields.ts` ([[secrets-encryption-at-rest]]).

**Standing and groups are cached for at most 60 s per session** (`session.ts:138-177`). Every page asset is one
check, and groups change rarely. Locking, deactivating and signing out are **not** delayed by the cache, because
they remove the session record, and the record is read on every check (`check.ts:190-199`). Only a group change
can take up to a minute to show.

## The implicit client `proxy.<bucketId>`

The sign-in is the project's own: an authorization-code request with PKCE (`S256`) and `scope=openid email`
through a client synthesized for the project, `proxy.<bucketId>` (`lib/behind_proxy/sign_in.ts:85-122`). Its
redirect URI is `<app address>/_foxauth/callback`. Like `account.<bucketId>` ([[connected-apps-page]]) and
`scim-<id>` ([[scim-provisioning]]), it is built on every resolution and stored nowhere. `tryFindClient` consults
it last, after the stored read (`lib/models/client/validate.ts:131-138`). Its redirect URIs are its apps'
callbacks, so they follow the apps without a second record to keep in step (`lib/behind_proxy/client.ts:46-67`).

- It **exists only while the project has at least one app**. A code client with nowhere to return to is not a client
  (`client.ts:54-55`). It is absent for the administrators' project, where a consent-free client for administrator
  accounts is what nobody should be able to point at, and for a project scheduled for deletion (`client.ts:50-52`).
- `consent.require: false` (`client.ts:65`). The project, not a third party, signs its own people in to its own app.
  Its redirect URIs count as operator-vouched, since only an administrator writes an app's address
  (`lib/models/client/provenance.ts:31-32`). The SL1 profile exempts it ([[ipsie-sl1-profile]]).
- It belongs to the project its id names, for bucket resolution and for `checkBucket`
  (`lib/admin/auth/resolveBucket.ts:62-64`, `lib/actions/authorization/check_bucket.ts:119-122`). Registration
  refuses the `proxy.` prefix (`lib/models/client/register.ts:147-153`). The person's sessions list and account page
  never show it as an application (`lib/end_users/sessions.ts:102-104`, `lib/account_page/routes.ts:318-323`).

**Its codes are redeemed in-process and refused at `/token`.** The callback redeems the code itself: the code
grant's checks (client, serving project, redirect URI, PKCE, grant, single consumption), then `findAccount`
(`sign_in.ts:188-243`). No token is minted. The public token endpoint refuses a code of this client as
`invalid_grant` (`lib/actions/token.ts:118-128`). Otherwise the endpoint would turn a session into tokens that the
app's people never asked for.

The callback is honoured once, only in the browser that started the sign-in, for the app and project it was started
for. The marker cookie's digest is compared **before** the pending record is consumed, so a crafted link carrying
someone else's `state` cannot use up a sign-in that is in progress (`sign_in.ts:142-168`). The return path is
limited to the app's own origin and never to a reserved path (`sign_in.ts:56-78`).

**Monthly active users.** A sign-in here issues no token, so `executeGrant` never sees it. The redemption calls
the activity writer `markActivity` directly, with the account `findAccount` resolved and the code's sign-in kind
(`sign_in.ts:237-241`, `lib/activity/note.ts:65-70`). `noteActivity` itself now delegates to `markActivity`. See
[[monthly-active-users]].

## What the app receives

`X-Auth-User` (the account id), `X-Auth-Email`, `X-Auth-Groups` and `X-Auth-Assertion` are **always present**. On
a public path, or with nobody signed in, they are present and empty (`check.ts:67-73`, `:212-224`). Leaving a header
out would let a value the browser sent survive a proxy that only overwrites the headers it receives. For the same
reason every recipe also strips incoming `X-Auth-*` before the request reaches the app (`recipes.ts:1-11`). A
public path names nobody, even for a person who has a session.

- `X-Auth-Groups` holds **group ids**, comma-joined and sorted (`check.ts:226`, `session.ts:171`). An id survives a
  rename; names go only in the signed assertion's `group_names`.
- `X-Auth-Email` is percent-encoded as UTF-8 (RFC 3986) for every character outside printable ASCII, and for `%`
  itself, so an app decodes every value the same way. A header carries Latin-1 at most, and proxies differ beyond
  ASCII (`check.ts:201-210`).
- A control character in the email or a group name is refused as `unsafe_value`, rather than sent as a header the
  proxy would split (`check.ts:328-342`).
- `X-Auth-Assertion` is a JWT signed with the project's own key through `keysFor` ([[signing-keys]]):
  `typ: foxauth-proxy+jwt`, `iss` the project's issuer, `aud` the app's address, `sub`, `email`, `groups`,
  `group_names`, and a 60-second lifetime (`lib/behind_proxy/assertion.ts:14-45`). An app that verifies it stops
  depending on being reachable only through the proxy.

A signed-in person whom the rules turn away is shown a plain-family denial page, answered 403 ([[interaction-page-families]]),
with "use another account" (sign-out, then a `prompt=login` sign-in). A request that is not a navigation, or a
status-only check, gets the bare status (`check.ts:239-261`, `lib/behind_proxy/pages.tsx:1-6`). A navigation with no
session is redirected to the sign-in. Anything else gets `401` with `WWW-Authenticate: FoxAuth`
(`check.ts:135-144`, `:349-360`).

## Deciding a path

`decide()` (`lib/behind_proxy/decide.ts:216-252`) imports nothing. The live check and the console's access check
both run it, so the two cannot disagree about the same person, request and rules (`decide.ts:1-7`).

**Canonicalisation looks at the raw path first** (`decide.ts:63-97`). Decoding `%2E` before looking would turn it
into a dot segment that resolves away, when it should be refused. These are refused as `ambiguous_path`: a control
character (raw or encoded), a path that is not absolute, a backslash, a `;`, an encoded `/`, `\` or `.`, and a broken
escape. Only escapes of unreserved characters are then decoded. A path where collapsing `//` before or after
resolving `..` gives different answers is refused too, because applications disagree on the order
(`decide.ts:86-95`). Whatever the app might read differently from this function is refused, not guessed at.

**The rule that decides** (`ruleFor`, `decide.ts:178-206`):

- The longest whole-segment prefix wins. `/admin` covers `/admin/x` but not `/administrator`
  (`decide.ts:165-171`). Rule order never matters.
- Matching ignores letter case, **except for public rules**, which match only with their exact case. Where two
  rules differ only in case, the closed one is tried first.
- A public rule covers **only `GET` and `HEAD`**, and only its exact path unless it is marked to cover its subtree.
  Where it does not cover a request, the next-longest rule decides, so a mistake in a public rule falls on the
  closed side.
- Kinds of rule: a list of groups, everyone in the project, public, or nobody. A person must also pass `canSignIn`.
  A deleted group admits nobody.

## Rate limit and caller

The check is `exempt` from the per-origin limiter (`lib/consts/route_classification.ts:597-602`), for the same
reason as SCIM: every person behind one proxy arrives from the proxy's one address
([[per-origin-rate-limiting]]). It is limited **per app** instead, 6000 checks a minute, deliberately not a setting
(`lib/behind_proxy/rate_limit.ts:26-57`). A check naming no app this project holds is charged to the caller with
the strict failed-credential bounds (`rate_limit.ts:72-77`). Under `mode=status` the flood refusal is a 403
(`check.ts:364-373`).

The caller is always the proxy, never the person it asks about. Where the proxy is trusted, `callerAddressOf` would
believe its `X-Forwarded-For`, which holds the browser's address. So the check replaces an address resolved from
that header with the connection it arrived on (`rate_limit.ts:59-70`, [[caller-address]]). The route is always
available and has no instance switch, because the endpoint does nothing until a project declares an app
(`route_classification.ts:323-327`).

## What is not recorded

**There is no per-request decision log.** Each decision is emitted as `behind_proxy.decision` on the
[[event-bus]], with identifiers only (no host, path or cookie) and nothing stored (`check.ts:109-122`,
`lib/event_bus.ts:245-258`). The owner decided that a per-user visit log is a later spec of its own. Every
page asset is one check, so such a log is a different storage and privacy decision.

**Usage writes are throttled** (`usage.ts:9-18`). The Connect page's checklist reads "first asked", "last asked",
"first sign-in" and "first let through". "Last asked" is written at most once a minute per app per server. Each
"first" is claimed in memory before its write, and the store writes it only where none is recorded yet. Nothing is
awaited, and a failure is captured, not answered (`usage.ts:21-102`).

## The console

- Apps are a **second table on the Applications tab**, below the OAuth clients. They are not OAuth clients, so they
  appear in no client list and do not count against a plan's application limit
  (`lib/admin/ui/pages/behind-proxy/BehindProxyTable.tsx:17-21`, `lib/admin/ui/pages/BucketDetail.tsx:361-374`).
  Each app has its own page with Connect, Access and Settings tabs. The admin routes audit every write and are
  published as five MCP tools ([[admin-mcp-control-plane]]).
- **Confirmation only when access widens.** A change of rules is judged by the access that results, not by which
  rows changed. `widenings()` decides every named path and its subtree under both rule sets, with a write method as
  well as a read, and lists what lets more people in (`decide.ts:254-305`). Narrowing saves at once. A widening asks
  a C2 confirmation listing each change. Making the root or a subtree public asks for the word `public`
  (`lib/admin/ui/frame/actions.ts:264-283`, `lib/admin/ui/pages/behind-proxy/AccessTab.tsx:290-315`).
- **The access check** ("who would get in, at this address") runs the same `decide()` in the browser. It runs on the
  saved rules and on the edited ones, with the person's standing and groups from the admin routes
  (`lib/behind_proxy/access_check.ts:1-17`, `:91-98`). There is no dry-run route, because it would need an audit
  entry for every click. A pasted address is split without the URL parser, so the check sees the same text the
  proxy would send (`access_check.ts:64-87`).
- The recipes for Caddy, Traefik and nginx come from one function, used by both the Connect tab and the site's
  recipe page ([[situation-guide]]; `recipes.ts:1-11`).

## Known limitations

- **A double-encoded separator is not refused.** `%252F` passes canonicalisation as literal text, because `%25` is
  not an unreserved escape and stays encoded (`decide.ts:78`, `:108-124`). An app that decodes twice would see `/`
  where the rules saw none.
- **Traefik and underscore aliases.** `authResponseHeadersRegex: "^X-Auth-"` strips `X-Auth-*` but not
  `X_Auth_User`. A framework that maps both spellings to one variable (CGI-style `HTTP_X_AUTH_USER`) could read a
  forged value. This stays possible unless the entry point is configured to drop headers with underscores.
- **The instance must be reachable over https.** The app's address must be `https` (`address.ts:37`), and its
  cookies are `Secure` and `__Host-`. A test instance with an `http` `ISSUER` proves the flow in-process only.
- **Keeping the app reachable only through the proxy is the operator's job.** A request that reaches the app
  another way skips the check, and the headers can then be forged. The guide and the site say so
  (`lib/consts/situation_guide.ts:1285`). Verifying `X-Auth-Assertion` is the defence an app can add for itself.

## Related

- [[project-is-an-issuer]] — the host-from-`Host` rule this endpoint is the one exception to.
- [[cookie-path-scoping]] — why the set and the expiry share one attribute writer.
- [[connected-apps-page]], [[scim-provisioning]] — the other two synthesized, never-stored clients.
- [[monthly-active-users]] — the one sign-in that counts without a token.
- [[end-user-lifecycle]], [[self-service-password-reset]] — the sweeps that end an app session.
- [[per-origin-rate-limiting]], [[caller-address]] — the exemption and the caller.
