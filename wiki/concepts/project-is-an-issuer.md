---
type: concept
title: 'A project is a tenant with its own issuer'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-15
updated: 2026-10-22
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:account-resolution
      source: oauth-server-codebase
      evidence: 'resolveBucketForRequest no longer decides a request project — the address does; it still answers which project a client belongs to.'
      confidence: high
      status: current
    - predicate: depends_on
      object: concept:cookie-path-scoping
      source: oauth-server-codebase
      evidence: 'The session cookie name now varies per project, which multiplies the identity rule that page states.'
      confidence: high
      status: current
---

# A project is a tenant with its own issuer

A project is stored as a bucket (`UserBucket`, area `userBuckets`), and the code keeps that name:
`issuerFor(bucket)`, `resolveBucketForRequest`, the `/:bucket` route segment and the `bucketId` a token
records. Until spec 100 the console and the admin API called it a bucket too; issuer URLs, discovery,
tokens and cookies did not change with the word.

A project named `acme` has issuer `https://auth.example.com/acme` and serves every endpoint beneath it.
**The default project has no prefix**: its issuer and endpoints are exactly what the server published
before tenancy existed, which is what makes the change deliverable without a flag day.

## The one asymmetry, and why it is correct rather than convenient

An issuer identifier is a promise already made. Clients are configured against
`https://auth.foxauth.dev`, and tokens carrying it are in circulation; renaming it serves nobody and
invalidates everyone. Nothing in OIDC requires a multi-tenant server to path-qualify every tenant —
Auth0's primary tenant is likewise the bare domain.

The cost is one branch, in one function, forever: `issuerFor(bucket)` in `lib/configs/issuer.ts`.
**Never inline it.** Across the call sites that need an issuer it becomes that many chances to forget
the root case, and the failure is a token whose `iss` does not match the metadata that advertised
the endpoint it came from — which clients reject with an error naming neither cause.

The branch tests `isServedAtTheRoot(bucketId)`, not the default project's id, and the difference is not
cosmetic. It shipped as `bucket._id === DEFAULT_BUCKET_ID` while the *routing* side already excluded
both reserved projects, so the administrators' project was unaddressable and yet issued
`<ISSUER>/admin` — an identifier no metadata advertises. Every agent connection to the admin MCP plane
signed in successfully and was then refused, because the client checked `iss` against what it had
discovered. One predicate now answers both questions, and `isAddressable` derives from it; two lists
of reserved ids is precisely how this returns.

Any later change that gives the default project a prefix, for uniformity or to remove that branch, is a
breaking release for every integration and every token in circulation, not a refactor.

## An issuer has one key set, and a project's is its own

A project with an address signs with keys of its own and advertises `jwks_uri` beneath its own issuer
(since 2026-09-29, [[signing-keys]]); everything served at the root shares the root's. Keys follow the
issuer, not the project record — which is why a project without an address has none of its own: it has no
issuer to publish them under. They are keyed by the project's id, so a move between any two address forms
(path, subdomain since spec 101, hostname) keeps them.

## Two reserved projects are not addressable

The administrators' project and the default project are served at the root by design: the default one is
the instance's own population, and the administrators' project is what the console authenticates against
as a relying party on the instance's issuer ([[admin-console-signin]]). Both carry a slug, because a
session cookie has to be named after something, but neither is reachable at a prefixed address —
admitting either would give one population two issuer identifiers, which is the one thing an issuer
identifier may not have.

This is why the console did **not** move off `/admin`: the move existed only to free that word for the
administrators' project, and the project never puts it in a URL.

**A project holds exactly one address form.** `056-host-addressed-buckets` introduced the second form, and
spec 101 (2026-10-15) the third. A named project carries one of:

- a path segment (`<ISSUER>/acme`);
- a subdomain of the instance (`https://acme.auth.example.com`, derived from the slug plus a `subdomain`
  marker; see [[subdomain-project-addresses]]);
- a hostname of its own (`https://login.acme.com`).

Two addresses would be two issuer identifiers for one population. Which state a project is in is one derived
answer, `addressOf` (`lib/configs/issuer.ts:42`): root, host, subdomain, path or unaddressed, tested in that
order. Subdomain is tested before path because a subdomain project has a slug too. `issuerFor` and
`sessionCookieName` switch on it rather than each re-inferring from the fields and a reserved-id predicate. A third consumer, `pathPrefixFor`, shipped
with `056` and was **removed** once a coverage report showed it had never had a caller: the router
mounts the same plugins under a dynamic `/:bucket` segment instead of building a prefix string, and the
console derives the string in `lib/admin/ui/bucketAddress.ts`, which cannot delegate here because it is
in the browser bundle and this module reads the environment. It returns a fourth state,
`unaddressed`, on purpose: `issuerFor` falls back to the record id for a project written before slugs
existed while the cookie falls back to `default`, and collapsing those two into one `path` state writes
a cookie the bare `/auth` never looks for — the sign-in completes and then does not exist.

Everything below about slugs continues to hold; a hostname simply takes the same place in the same
rules. Three consequences are specific to the host form. Since spec 101 they hold for a subdomain project as
well, since it also has an origin of its own (`hasOwnOrigin`, `lib/configs/issuer.ts:145`). The request's host is read in one place
(`hostOfRequest`), from `Host` and never `X-Forwarded-Host`, because that header is attacker-settable
and here it selects the tenant. A host-addressed project needs only the single well-known location, since
its issuer is an origin with no path and the two specifications stop disagreeing. And an interaction now
records the project it began at, because `/ui/*` is served from one origin for every path-addressed
project but a hostname makes the origin a real boundary — without the record, an interaction begun at one
project's host could be completed at another's, writing a session cookie named for the first onto the
origin of the second.

**Not every unknown host is refused.** A server answers at more names than its canonical one —
`localhost`, the platform's own name, the address a health check uses — so the rule keys on the
deployment's own domain (`isWithinDeploymentDomain`, `lib/admin/auth/bucketAddress.ts:183`). A name
beneath the canonical host that no project holds is a typo of a tenant address and is refused, since
serving the default population there would make the mistake look like it worked; a name outside it
resolves by path, as every request did before hostnames. Refusing both would take the deployment off
the air everywhere except the exact URL in `ISSUER`.

**Changing an address changes the issuer**, so it is not a field on the project PATCH. It is its own
route, `POST /admin/api/projects/:id/address` (`lib/admin/buckets/routes.ts:1171`), which answers with a
preview until called with `confirm: true`, and is audited as its own action — stored as
`bucket.address.change` (`lib/consts/admin_audit_routes.ts:257`), shown in the trail as
`project.address.change`. Since spec 101 the entry records `from`/`to` as issuer URLs (`:1249-1251`), because a
path `acme` and a subdomain `acme` share a slug; earlier entries keep a slug or a hostname. Since spec 081 the preview names what breaks — each application (until spec
099, with the retired project it sat in), each provisioning connection, each identity provider with its
new callback address, each declared resource — and the confirming call must repeat the preview's counts
(`expect`), or it is refused with a fresh preview. A team owner may change a **path** — since spec 101 a
**path or subdomain**, into a form `can.addressForms` lists — while nothing depends on the project (no
application — before spec 099, no retired project either — provider or connection); a host stays
super-administrator-only. The change clears the project's recorded host
arrivals, so a new host does not read as reached from the old one's traffic. See [[project-workspace]].

**A slug is a name, not an address**, and three places need to know the difference: `issuerFor`, which
stamps `iss` into every token; `isAddressable`, which decides whether an address resolves — and which now
accepts either form, so testing the slug alone would declare every host-addressed project unaddressable;
and the console's Projects table (the Buckets table until spec 100), whose Address column is what an
operator copies when pointing a client at a project. `isServedAtTheRoot` in `lib/admin/consts.ts` is the
single predicate all three derive from,
and it lives in that import-free module for the third of them — the browser bundle can reach no module
that touches the configuration layer, which is why the rule could not simply live beside `issuerFor`.

Each pair of them that once disagreed produced a defect of the same shape. Routing against issuing gave
the administrators' project no address and yet an `<ISSUER>/admin` identifier, so a genuine sign-in minted
a token no client would accept. The console against both rendered any slug it found, so the table (then
the Buckets table) advertised the default project at `/default` — a path that answers 404 — as the place
to integrate a client. The console's decision is `bucketAddressFor` in `lib/admin/ui/bucketAddress.ts`,
extracted from the table's render function so `test/bucket_addressing/console_address.spec.ts` can check
every listed project's address against the router that has to serve it.

## A browser may hold a sign-in in each project

A session cookie is named after the project that wrote it — `_session_default`, `_session_acme` — so
two sign-ins in one browser are two cookies and neither disturbs the other. A request reads the one
its project names and never looks for the other.

That project is the address for every endpoint but one. The two projects served at the root share an
address, so `/auth` resolves the population from the *client* instead (`OIDCContext.signInBucket`,
assigned from `checkBucket`'s resolution) — see [[cookie-path-scoping]] for the sign-in this
disagreement broke.

**A project on its own origin needs no such suffix and gets the bare `_session`.** That means a
host-addressed project and, since spec 101, a subdomain project (`lib/consts/param_list.ts:268-270`). The
suffix exists only because path-addressed projects share one origin; a project on its own origin already has
its cookie kept apart by the browser, since nothing here sets a `Domain` attribute. Which name is produced
follows from `addressOf`, not from whether a slug is present. A host-addressed project has no slug and must
not fall into the branch written for a project that has no address at all. A subdomain project *does* keep its
slug and must not fall into the path branch.

This did not ship with the rest of the feature, and the gap was not visible from the outside: the
projects *were* isolated — reaching one while signed in to another asked you to sign in, correctly —
but the second sign-in overwrote the first, so an end user was silently signed out of an application
they had not touched. Isolation and co-existence are different properties, and the tests that proved
the first said nothing about the second.

**The name was right and the project handed to it was not (fixed 2026-09-24).** `issuingBucket`
(`lib/admin/auth/bucketAddress.ts`) — the record every path uses once it knows a project id: the
sign-in screens, the interaction resume, token issuance — returned `{ _id, slug }` and dropped `host`.
`addressOf` then took a host-addressed project for one with no address, so its sign-in wrote
`_session_default` (a cookie its host, which reads `_session`, never looked for — every sign-in there
was forgotten) and its authorization responses and tokens named `ISSUER/<id>` while its discovery
document named its origin. The host now travels with the slug. `GET /logout` had the other half: it
resolved the project without the request host, so at a project's host it read the default project's session.
The existing cases passed through both, because they asserted the metadata's issuer and a refusal —
`test/host_buckets/addressing.spec.ts` now completes a sign-in and a sign-out at the host and reads
`iss` off the authorization response. Since spec 101 the subdomain marker travels the same way
(`requestBucketOf`, `lib/admin/auth/bucketAddress.ts:350`), since a subdomain project read back without it
would be taken for a path one.

**The path-addressed half of the sign-out (fixed 2026-09-30, spec 064).** The confirmation form
rendered by `/:bucket/logout` posted to the root-relative `/logout/confirm` — the *default* project's
confirmation, which reads a different session cookie and answered "could not find logout details". A
host-addressed project was spared only because a root-relative path resolves against its own host.
`logout()` (`lib/html/logout.tsx`) now takes the confirmation address, built from the addressed
issuer. `test/end_session/per_bucket.spec.ts` had claimed to follow the form the browser is shown
while building the prefixed URL itself; it now reads the form's `action`, and so does the host case.
Since 2026-10-13 that address is the confirmation's origin-relative path (`/acme/logout/confirm`): built
absolute from a host-addressed project's issuer, it read as a foreign form target and left the page framable
([[html-response-security-policy]]).

The path stays `/` for every project and deliberately does not carry the partition. It would, if every
project were prefixed — but the default project is served at the root, so its cookie must live at
`Path=/`, and a cookie at `Path=/` is sent to every other project's path anyway. Path scoping would
isolate the named projects from each other and fail on the one project every existing deployment uses.
See [[cookie-path-scoping]] for the identity rule this multiplies.

Two things fall out of the cookies being separate rather than needing their own code: a sign-out at
one project's address ends that project's sign-in and no other, and "Remember me" declined in one
project says nothing about another's lifetime.

## What the address decides, and what it does not

The address decides which population a request concerns. `resolveBucketForRequest` no longer answers
that; it answers which project a given *client* belongs to, and the two are compared —
`lib/actions/authorization/check_bucket.ts` refuses a client used at a project it does not belong to.
That refusal is a security invariant rather than a validation: without it the prefix would become a way
to move a client into a population its operator never put it in, which is the exact thing the rules in
`resolveBucket.ts` were written to prevent from the other direction.

**Addressable is the qualifier that makes the refusal correct rather than merely strict.** A project
with no slug has no endpoints of its own, so its clients have nowhere to go but the bare ones; refusing
them there strands every one of them. An unaddressed project keeps exactly the behaviour it had before
tenancy, and the check begins to apply the moment an operator gives it an address.

**It guards every endpoint that starts a flow, not only `/auth`.** Device authorization and backchannel
authentication also store an artifact that records the project it was started at, and the token issued
from it inherits that project. Until `060-typed-oidc-context` both built their context without a project,
so a flow at `/acme/device/auth` recorded the default project and yielded the instance's `iss` — and that
was the only reason they did not need the refusal. Honouring their address without it would have let a
default client start a flow at `acme` and receive `acme`-issued tokens, so both now call `checkBucket`
after the resource is final and before anything is stored (`lib/actions/authorization/device.ts`).
Registration also honours its address, for the management URI it returns and — corrected 2026-10-05 —
for the client it creates. A registration at a project's own address records that project on the client
(`bucketId`, `lib/actions/registration.ts:229`; a separate `registeredAtBucket`, read right after the rule
for the old Project entity — the retired project — until spec 099 folded both into the one field), and
`resolveBucketForRequest` pins the client to it exactly as it pins an administrator-created application,
so the client signs in that project's end users and is refused at any other address
([[project-is-the-only-container]]).
Before, a registration named no project: a client that followed `/acme`'s discovery to `/acme/reg` was
the default project's, refused `unauthorized_client` at `/acme/auth` and accepted at the bare `/auth` —
found by running the conformance suite against a named project. A registration at the root records
nothing, and the field is written from the address alone, never from the body.

**And the endpoints that authenticate a client** (spec 110, 2026-10-22). `checkBucket` guarded only the
endpoints that start a flow, so a client of `acme` could call `/globex/token` with client credentials and get a
token bearing `globex`'s issuer, or introspect and revoke there. RFC 6749 §2.2 makes a client identifier unique
to the server that issued it, and MCP's SEP-2352 tells clients the same from their side. `assertClientServedHere`
(`lib/actions/authorization/check_bucket.ts`), called by `tokenAuth` right after the client is found and before
any credential is checked, refuses a client pinned to another addressable project — token, introspection,
revocation, PAR, device authorization and backchannel authentication alike — with the exact answer an unknown
client gets. It reads only the project a client is pinned to, never a requested resource: rule 3 is safe at
`/auth` because the code it yields is bound to the project, and the one grant with no earlier step, client
credentials, now serves only the addressed project's own clients there. Registration management answers a
registration access token presented at another address as a token that does not exist, and keeps it. A
client of no project, and a document client (portable across issuers, SEP-2352), keep their reach; the
artifacts they get are what binds them.

**A client assertion is audienced at the addressed issuer.** Corrected 2026-10-05: the accepted `aud`
values (`lib/shared/token_jwt_auth.ts`) were the instance's — `ISSUER`, its token endpoint and the
bare route — at every address, so an assertion naming `/acme/token` was refused at `/acme/token` while
one naming the root was accepted there, and FAPI's single-issuer rule compared against the root too.
They are now `issuerFor(oidc.bucket)` and the endpoints beneath it; the route is stripped of its
`/:bucket` pattern first, since the matched route is a pattern, not a path.

**So is a DPoP proof's `htu`.** Corrected the same day, for the same reason: `dpopValidate`
(`lib/helpers/validate_dpop.ts`) compared `htu` with `ISSUER + route`, so at `/acme/token` a proof naming
`/acme/token` was refused `invalid_dpop_proof` and every DPoP-bound flow at a named project failed at the
token exchange — found by FAPI 2.0 run against `/named`. The addressed issuer is now a required
argument: the token endpoint, PAR and userinfo pass `issuerFor(oidc.bucket)`, and `/mcp`, served at the
root only, passes `ISSUER` explicitly.

**`oidc.route` is the bare endpoint at every address.** Elysia hands a handler the matched pattern, so at
a project's address the route was `/:bucket/par`, and every comparison against a bare name quietly took
the other branch — a pushed request with an unregistered `redirect_uri` was refused with the
registration code `invalid_redirect_uri` instead of `invalid_request` (RFC 9126 §2.3), and the PAR-only
`par.allowUnregisteredRedirectUris` allowance never applied. `OIDCContext` now strips the prefix once,
in its constructor (`lib/helpers/oidc_context.ts`); which project was addressed is `oidc.bucket`'s to say.

**And a request object's `aud`.** Corrected the same day: `processRequestObject` checked a signed request
object against the instance's identifier, so every FAPI 2.0 Message Signing push at `/named/par` was
refused 400. It now expects `issuerFor(oidc.bucket)`, and the unsigned request PAR stores for a plain
push carries the same audience (`pushed_authorization_request_response.ts`) — so a `request_uri` handed
out by one issuer is not accepted by another.

## A token records the project that issued it

`bucketId` is declared on `BaseTokenPayload` and set at issuance. Recorded, not derived, and the reason
is RFC 7662 §2.2: `active: true` asserts that *this* authorization server issued the token, and every
project is its own authorization server. A token of one project presented to another must be inactive,
and answering that requires knowing who issued it. Deriving the issuer from the client instead gets it
wrong the first time a client changes container (until spec 099 a client could move between the old
Project entities, the retired projects) — and a realm-confusion advisory against a Keycloak integration
is the same defect from the other end, a token of one realm silently accepted by a policy configured for
another.

A token minted before the field existed records nothing, and reading that absence as the default project
is exact rather than a fallback: the default project's issuer *is* the bare one such a token was minted
with.

**Introspection compares the serving project, not the recorded one** (fixed 2026-10-22). Until then
`lib/actions/introspection.ts` compared the recorded id with the addressed project, and a token issued at the root
to an application of a project with **no** address — signed in through the sign-in screens, which record the
project the sign-in resolved — was reported `active: false` by the root, the very server that issued it. A token
obtained from an existing session recorded the default project instead, which is why nothing had noticed. It now
compares `servingBucketIdOf`, as the grants do; `test/bucket_addressing/unaddressed_introspection.spec.ts` is the
case.

Tokens minted against a stored artifact inherit the artifact's project — the issuer is a fact about where the
grant was established. Since spec 110 (2026-10-22) the artifact is also **redeemable only there**: an
authorization code, refresh token, device code or backchannel request presented at another issuer's token
endpoint is refused `invalid_grant` before anything consumes, rotates or revokes it, so it still works where it
belongs. Until then a code issued at `/acme` redeemed at the root, and a refresh token kept refreshing wherever
it was sent. The comparison is `servingBucketIdOf` (`lib/admin/auth/bucketAddress.ts`), not the recorded id:
a sign-in for a project with no address runs at the root and records that project's id, yet its redemption is
addressed as the default project — every project served at the root shares the one issuer there. A project
with an address answers as itself, so a move between address forms keeps its artifacts; a deleted one answers
as itself too, and so matches nothing.

**A project that is given its first address keeps its sign-ins.** A browser sign-in records the project it
resolved — for a project with no address, that project's own id, not the default's — and a refresh token
inherits it. Once the project has an address, `servingBucketIdOf` answers with its id, so those tokens refresh
at the new address (and the tokens they mint carry its issuer, as the console warns: `BucketSettings.tsx`,
"reconfigured with the new issuer") and no longer at the root, where the project's clients are now refused
anyway. A device or backchannel request records the address it was started at, so one still pending at that
moment is redeemable at the root only, and its client is refused there: it has to be started again.

## Six things that cost a debugging session each

**Two well-known locations, built differently.** A path-bearing issuer has both: OIDC Discovery
*appends* the segment to the issuer, RFC 8414 *inserts* it between host and path. For `acme` that is
`/acme/.well-known/openid-configuration` and `/.well-known/openid-configuration/acme`. Serving only the
appended form passes every local test and fails conformance.

**`new URL(route, issuer)` discards the issuer's path.** `new URL('/auth', 'https://host/acme')` yields
`https://host/auth`, because a leading slash makes the path absolute. Correct URL resolution and
exactly wrong here — it advertises a named project's endpoints at the default project's address.
Concatenate.

**The resumed request builds its own context.** A sign-in through the interaction screens produces its
authorization response in `resume()`, which knows nothing of the address the flow started at. It
recovers the project from the stored interaction's parameters — the same ones the sign-in screen
resolved its own project from. Forgotten, the response carries the instance's `iss` while the metadata
promised the project's. The device flow's resumption (`ui/:uid/device_resume`) had forgotten it until
`060-typed-oidc-context`: the sign-in still completed, but was written to `_session_default` for a
named project's client's end user.

**Metadata can advertise an endpoint nobody mounted.** `test/bucket_addressing/advertised_endpoints.spec.ts`
enumerates what a project's document advertises and checks each is served. It was written because four
endpoints were advertised and not mounted, and no example-based test can close that gap: the defect is
the endpoint somebody forgot.

**Classification is derived, not listed.** `lib/consts/route_classification.ts` builds each table's
project-scoped entries from its bare ones. A second hand-written table states the rule "a project's
endpoints are the server's endpoints at a different address" in a form able to disagree with the first,
and the four guards over that file make the wrong repair obvious: paste twenty more entries rather than
notice they are all the same entry.

**Probe elysia with a real host.** A request to a single-label host (`http://x/…`) matches no route,
which reads as a framework limitation and nearly cost a redesign. Measured facts: the same plugin
instance mounts bare and beneath `/:bucket`, both routes answer, and a static route wins over a dynamic
first segment.
