---
type: concept
title: 'A user bucket is a tenant with its own issuer'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-15
updated: 2026-09-23
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:account-resolution
      source: oauth-server-codebase
      evidence: 'resolveBucketForRequest no longer decides a request bucket — the address does; it still answers which bucket a client belongs to.'
      confidence: high
      status: current
    - predicate: depends_on
      object: concept:cookie-path-scoping
      source: oauth-server-codebase
      evidence: 'The session cookie name now varies per bucket, which multiplies the identity rule that page states.'
      confidence: high
      status: current
---

# A user bucket is a tenant with its own issuer

A bucket named `acme` has issuer `https://auth.example.com/acme` and serves every endpoint beneath it.
**The default bucket has no prefix**: its issuer and endpoints are exactly what the server published
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

The branch tests `isServedAtTheRoot(bucketId)`, not the default bucket's id, and the difference is not
cosmetic. It shipped as `bucket._id === DEFAULT_BUCKET_ID` while the *routing* side already excluded
both reserved buckets, so the administrators bucket was unaddressable and yet issued
`<ISSUER>/admin` — an identifier no metadata advertises. Every agent connection to the admin MCP plane
signed in successfully and was then refused, because the client checked `iss` against what it had
discovered. One predicate now answers both questions, and `isAddressable` derives from it; two lists
of reserved ids is precisely how this returns.

Any later change that gives the default bucket a prefix, for uniformity or to remove that branch, is a
breaking release for every integration and every token in circulation, not a refactor.

## Two reserved buckets are not addressable

The administrators bucket and the default bucket are served at the root by design: the default one is
the instance's own population, and the administrators bucket is what the console authenticates against
as a relying party on the instance's issuer ([[admin-console-signin]]). Both carry a slug, because a
session cookie has to be named after something, but neither is reachable at a prefixed address —
admitting either would give one population two issuer identifiers, which is the one thing an issuer
identifier may not have.

This is why the console did **not** move off `/admin`: the move existed only to free that word for the
administrators bucket, and the bucket never puts it in a URL.

**As of `056-host-addressed-buckets` there are two address forms, and a bucket holds exactly one.** A
named bucket carries a path segment (`<ISSUER>/acme`) **or** a hostname of its own
(`https://acme.auth.example.com`), never both — two addresses would be two issuer identifiers for one
population. Which of the three states a bucket is in is now one derived answer, `addressOf` in
`lib/configs/issuer.ts`, and `issuerFor` and `sessionCookieName` switch on it rather than each
re-inferring from two fields and a reserved-id predicate. A third consumer, `pathPrefixFor`, shipped
with `056` and was **removed** once a coverage report showed it had never had a caller: the router
mounts the same plugins under a dynamic `/:bucket` segment instead of building a prefix string, and the
console derives the string in `lib/admin/ui/bucketAddress.ts`, which cannot delegate here because it is
in the browser bundle and this module reads the environment. It returns a fourth state,
`unaddressed`, on purpose: `issuerFor` falls back to the record id for a bucket written before slugs
existed while the cookie falls back to `default`, and collapsing those two into one `path` state writes
a cookie the bare `/auth` never looks for — the sign-in completes and then does not exist.

Everything below about slugs continues to hold; a hostname simply takes the same place in the same
rules. Three consequences are specific to the host form. The request's host is read in one place
(`hostOfRequest`), from `Host` and never `X-Forwarded-Host`, because that header is attacker-settable
and here it selects the tenant. A host-addressed bucket needs only the single well-known location, since
its issuer is an origin with no path and the two specifications stop disagreeing. And an interaction now
records the bucket it began at, because `/ui/*` is served from one origin for every path-addressed
bucket but a hostname makes the origin a real boundary — without the record, an interaction begun at one
bucket's host could be completed at another's, writing a session cookie named for the first onto the
origin of the second.

**Not every unknown host is refused.** A server answers at more names than its canonical one —
`localhost`, the platform's own name, the address a health check uses — so the rule keys on the
deployment's own domain (`isWithinDeploymentDomain`, `lib/admin/auth/bucketAddress.ts:122`). A name
beneath the canonical host that no bucket holds is a typo of a tenant address and is refused, since
serving the default population there would make the mistake look like it worked; a name outside it
resolves by path, as every request did before hostnames. Refusing both would take the deployment off
the air everywhere except the exact URL in `ISSUER`.

**Changing an address changes the issuer**, so it is not a field on the bucket PATCH. It is its own
route, `POST /admin/api/buckets/:id/address` (`lib/admin/buckets/routes.ts:404`), which answers with a
preview until called with `confirm: true`, and is audited as its own action, `bucket.address.change`
(`lib/consts/admin_audit_routes.ts:264`).

**A slug is a name, not an address**, and three places need to know the difference: `issuerFor`, which
stamps `iss` into every token; `isAddressable`, which decides whether an address resolves — and which now
accepts either form, so testing the slug alone would declare every host-addressed bucket unaddressable;
and the console's Buckets table, whose Address column is what an operator copies when pointing a client at
a bucket. `isServedAtTheRoot` in `lib/admin/consts.ts` is the single predicate all three derive from,
and it lives in that import-free module for the third of them — the browser bundle can reach no module
that touches the configuration layer, which is why the rule could not simply live beside `issuerFor`.

Each pair of them that once disagreed produced a defect of the same shape. Routing against issuing gave
the administrators bucket no address and yet an `<ISSUER>/admin` identifier, so a genuine sign-in minted
a token no client would accept. The console against both rendered any slug it found, so the Buckets
table advertised the default bucket at `/default` — a path that answers 404 — as the place to integrate
a client. The console's decision is `bucketAddressFor` in `lib/admin/ui/bucketAddress.ts`, extracted
from the table's render function so `test/bucket_addressing/console_address.spec.ts` can check every
listed bucket's address against the router that has to serve it.

## A browser may hold a sign-in in each bucket

A session cookie is named after the bucket that wrote it — `_session_default`, `_session_acme` — so
two sign-ins in one browser are two cookies and neither disturbs the other. A request reads the one
its bucket names and never looks for the other.

That bucket is the address for every endpoint but one. The two buckets served at the root share an
address, so `/auth` resolves the population from the *client* instead (`OIDCContext.signInBucket`,
assigned from `checkBucket`'s resolution) — see [[cookie-path-scoping]] for the sign-in this
disagreement broke.

**A host-addressed bucket needs no such suffix and gets the bare `_session`.** The suffix exists only
because path-addressed buckets share one origin; a bucket on its own origin already has its cookie kept
apart by the browser, since nothing here sets a `Domain` attribute. Which name is produced follows from
`addressOf`, not from whether a slug is present — a host-addressed bucket has no slug and must not fall
into the branch written for a bucket that has no address at all.

This did not ship with the rest of the feature, and the gap was not visible from the outside: the
buckets *were* isolated — reaching one while signed in to another asked you to sign in, correctly —
but the second sign-in overwrote the first, so an end user was silently signed out of an application
they had not touched. Isolation and co-existence are different properties, and the tests that proved
the first said nothing about the second.

The path stays `/` for every bucket and deliberately does not carry the partition. It would, if every
bucket were prefixed — but the default bucket is served at the root, so its cookie must live at
`Path=/`, and a cookie at `Path=/` is sent to every other bucket's path anyway. Path scoping would
isolate the named buckets from each other and fail on the one bucket every existing deployment uses.
See [[cookie-path-scoping]] for the identity rule this multiplies.

Two things fall out of the cookies being separate rather than needing their own code: a sign-out at
one bucket's address ends that bucket's sign-in and no other, and "Remember me" declined in one
bucket says nothing about another's lifetime.

## What the address decides, and what it does not

The address decides which population a request concerns. `resolveBucketForRequest` no longer answers
that; it answers which bucket a given *client* belongs to, and the two are compared —
`lib/actions/authorization/check_bucket.ts` refuses a client used at a bucket it does not belong to.
That refusal is a security invariant rather than a validation: without it the prefix would become a way
to move a client into a population its operator never put it in, which is the exact thing the rules in
`resolveBucket.ts` were written to prevent from the other direction.

**Addressable is the qualifier that makes the refusal correct rather than merely strict.** A bucket
with no slug has no endpoints of its own, so its clients have nowhere to go but the bare ones; refusing
them there strands every one of them. An unaddressed bucket keeps exactly the behaviour it had before
tenancy, and the check begins to apply the moment an operator gives it an address.

**It guards every endpoint that starts a flow, not only `/auth`.** Device authorization and backchannel
authentication also store an artifact that records the bucket it was started at, and the token issued
from it inherits that bucket. Until `060-typed-oidc-context` both built their context without a bucket,
so a flow at `/acme/device/auth` recorded the default bucket and yielded the instance's `iss` — and that
was the only reason they did not need the refusal. Honouring their address without it would have let a
default client start a flow at `acme` and receive `acme`-issued tokens, so both now call `checkBucket`
after the resource is final and before anything is stored (`lib/actions/authorization/device.ts`).
Registration also honours its address, for the management URI it returns, but refuses nothing: a
registration names no bucket.

## A token records the bucket that issued it

`bucketId` is declared on `BaseTokenPayload` and set at issuance. Recorded, not derived, and the reason
is RFC 7662 §2.2: `active: true` asserts that *this* authorization server issued the token, and every
bucket is its own authorization server. A token of one bucket presented to another must be inactive,
and answering that requires knowing who issued it. Deriving the issuer from the client instead gets it
wrong the first time a client moves between projects — and a realm-confusion advisory against a
Keycloak integration is the same defect from the other end, a token of one realm silently accepted by a
policy configured for another.

A token minted before the field existed records nothing, and reading that absence as the default bucket
is exact rather than a fallback: the default bucket's issuer *is* the bare one such a token was minted
with.

Tokens minted against a stored artifact inherit the artifact's bucket rather than the address the
redemption arrived at — the issuer is a fact about where the grant was established.

## Six things that cost a debugging session each

**Two well-known locations, built differently.** A path-bearing issuer has both: OIDC Discovery
*appends* the segment to the issuer, RFC 8414 *inserts* it between host and path. For `acme` that is
`/acme/.well-known/openid-configuration` and `/.well-known/openid-configuration/acme`. Serving only the
appended form passes every local test and fails conformance.

**`new URL(route, issuer)` discards the issuer's path.** `new URL('/auth', 'https://host/acme')` yields
`https://host/auth`, because a leading slash makes the path absolute. Correct URL resolution and
exactly wrong here — it advertises a named bucket's endpoints at the default bucket's address.
Concatenate.

**The resumed request builds its own context.** A sign-in through the interaction screens produces its
authorization response in `resume()`, which knows nothing of the address the flow started at. It
recovers the bucket from the stored interaction's parameters — the same ones the sign-in screen
resolved its own bucket from. Forgotten, the response carries the instance's `iss` while the metadata
promised the bucket's. The device flow's resumption (`ui/:uid/device_resume`) had forgotten it until
`060-typed-oidc-context`: the sign-in still completed, but was written to `_session_default` for a
bucket client's end user.

**Metadata can advertise an endpoint nobody mounted.** `test/bucket_addressing/advertised_endpoints.spec.ts`
enumerates what a bucket's document advertises and checks each is served. It was written because four
endpoints were advertised and not mounted, and no example-based test can close that gap: the defect is
the endpoint somebody forgot.

**Classification is derived, not listed.** `lib/consts/route_classification.ts` builds each table's
bucket-scoped entries from its bare ones. A second hand-written table states the rule "a bucket's
endpoints are the server's endpoints at a different address" in a form able to disagree with the first,
and the four guards over that file make the wrong repair obvious: paste twenty more entries rather than
notice they are all the same entry.

**Probe elysia with a real host.** A request to a single-label host (`http://x/…`) matches no route,
which reads as a framework limitation and nearly cost a redesign. Measured facts: the same plugin
instance mounts bare and beneath `/:bucket`, both routes answer, and a static route wins over a dynamic
first segment.
