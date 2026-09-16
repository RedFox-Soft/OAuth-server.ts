---
type: concept
title: 'A user bucket is a tenant with its own issuer'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-15
updated: 2026-09-15
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
the default case, and the failure is a token whose `iss` does not match the metadata that advertised
the endpoint it came from — which clients reject with an error naming neither cause.

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
promised the bucket's.

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
