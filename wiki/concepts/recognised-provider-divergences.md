---
type: concept
title: 'Why Microsoft, Apple and GitHub each needed more than a catalogue row'
tags: [architecture, gotcha, oidc, contract]
sources: [oauth-server-codebase]
created: 2026-09-17
updated: 2026-09-17
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:upstream-federation
      source: oauth-server-codebase
      evidence: 'identityFor(provider, entry) dispatches on the matched entry protocol'
      confidence: high
      status: current
---

# Why Microsoft, Apple and GitHub each needed more than a catalogue row

`specs/052-google-provider-onboarding` shipped the recognised-provider catalogue and closed with the
assumption that the remaining providers would be "a matter of adding data". `specs/053-apple-microsoft-github`
found that **false for all three, in three different ways**. Each is a fact about somebody else's product,
so none of them will go away; they are recorded here because each one is invisible until it fails, and two
of the three fail months or years after the change that caused them.

## The seam that made it tractable

`resolveFederatedAccount({ bucket, provider, subject, claims })` takes a plain claims record and knows
nothing about ID tokens. So the whole decision ladder — the part where an ordering mistake is a
vulnerability — was **already** protocol-agnostic. The work divided at that line:

- above it, `lib/federation/identity/` obtains `(subject, claims)`, by one of two protocols;
- below it, nothing changed. `resolve.ts` is untouched by the entire feature.

Finding that seam was most of the design. A second sign-in route, or a synthesised assertion fed to the
existing verifier, would both have meant a second copy of the ladder.

## Microsoft: the issuer is not a string

Microsoft's issuer contains the organisation, so no fixed value can equal every deployment's. Worse, the
metadata it publishes for `common` and `organizations` states the issuer as the **literal placeholder**
`https://login.microsoftonline.com/{tenantid}/v2.0`. Two consequences:

- equality matching had to become `issuerRule`, a pattern for that entry;
- `discovery.ts`'s §4.3 check — the document's issuer must equal the one used to fetch it — cannot be
  satisfied at all, and is therefore compared against the pattern **only** for an entry declaring itself
  templated. The equality rule survives for every other upstream, where a mismatched issuer is a genuine
  attack signal.

`jwtVerify` takes issuers as strings, not patterns, so `verifyFederatedIdToken` grew an `acceptIssuer`
predicate. It replaces the string comparison; it does not remove it.

**What actually restricts who may sign in is the `tid` claim, not the issuer.** With a multi-organisation
endpoint any organisation's assertion verifies correctly, so without that check a connection "restricted"
to one company would admit the world — and Microsoft's own claims reference instructs an application to
do exactly this restriction itself. A missing claim fails closed.

Its address claim is also not guaranteed: `email` is present by default only for guests, and the fallback
`preferred_username` is documented as possibly a phone number or a bare username. It is used only when the
value looks like an address, because provisioning an account under a phone number reaches nobody and could
collide with another such string.

## Apple: the credential expires, and that is the whole point

Apple issues **no client secret**. It issues an ES256 signing key, and the value presented at its token
endpoint is an assertion derived from that key which Apple refuses if valid for more than 15,777,000
seconds — six months. So any *stored* credential is an outage with a date on it: sign-in works until one
morning it does not, the failure appears on Apple's page as a bare `invalid_client`, nothing here changed,
and there is nothing local to diagnose it by.

`lib/federation/apple_secret.ts` therefore mints one per exchange. Not cached: a cache reintroduces the
same expiry in miniature, plus a clock dependency and a renewal to get wrong, to save one signature on a
path that already makes a network round trip.

Two more Apple facts, both easy to discover the hard way:

- **The posting-back return is mandatory, not optional.** Ask for a name or an address and Apple refuses
  the authorization request outright unless `response_mode=form_post`. `POST /federation/callback` exists
  for this, on the *same path* as the GET — the reason the callback reads no cookie is that the
  interaction cookie is scoped `path: /ui/${uid}`, which is a property of the path and not the method.
- **A person's name arrives once, ever**, on their first authorization. And the scope granted on that
  first occasion is what Apple honours forever after: asking for more later recovers nothing until the
  person revokes the application in their own Apple settings.

## GitHub: it asserts no identity

GitHub is not an OpenID Connect provider for signing a person in. It publishes no metadata document and
issues no assertion; the sign-in yields only a token for calling its API, and who signed in must be read
back afterwards.

**It does publish one OIDC document**, at `token.actions.githubusercontent.com`, and this is worth stating
precisely so nobody reopens it: that one describes machine identity for GitHub Actions workflows. It has
no `authorization_endpoint` and its only supported response is a bare assertion, so no human can be sent
to it. Checked live on 2026-09-17; `github.com/.well-known/openid-configuration` is 404.

So `identity/profile_api.ts` exchanges the code and hands the token to a named reader, and
`identity/github.ts` reads the profile and — when the profile hides an address — the account's addresses,
taking the **primary verified** one. Three things there are load-bearing:

- the subject is the numeric id, never the login, which can be renamed and the freed name claimed by
  somebody else. The ladder treats the subject as opaque and would have linked either happily.
- `email_verified` is set only for an address GitHub itself marks verified. `emailTrusted: true` on the
  entry is safe *only* because of that; an unverified GitHub address arriving as verified would be a
  takeover through the linking step.
- the token does not outlive the read, keeping the existing rule about upstream tokens.

Two quirks that make a correct implementation work and an otherwise-correct one fail confusingly: the
token endpoint answers form-encoded unless JSON is asked for (a form-encoded body parses as JSON into
nothing, so the token reads as `undefined` and the sign-in fails as though the code were invalid), and
`api.github.com` rejects a request carrying no user-agent with a 403 that reads like a permissions
problem.

## The finding that was not about the new providers

This server decided whether to bind the authorization code to its request by reading
`code_challenge_methods_supported`. Live checks: Google advertises it, **Microsoft and Apple advertise
nothing, and GitHub publishes no document at all** — while Microsoft's documentation recommends the
binding "for all application types, both public and confidential clients" and GitHub has supported `S256`
since 14 July 2025.

So three of the four legs silently got no binding. That is a weakness in what `specs/052` shipped, not a
cost of what `specs/053` added, and it also improves any hand-configured provider whose upstream
under-reports. The rule now: a recognised entry's `codeBinding` wins over metadata, metadata decides for
anything unrecognised, and `unknown` sends nothing — because a provider that rejects a parameter it does
not recognise fails sign-in for *all* its users, so a missing binding is a weakness while a rejected
authorization request is a total outage.

**Apple's support is unresolved.** It advertises no method and the public record contradicts itself (2019:
became compliant "having previously excluded" PKCE; 2021: unsupported). Its entry says `unknown` until
somebody settles it against a real credential.

## Gotchas found while building it

### The masking is one function, and it must stay that way

A provider's secret leaked for a year because `present()` guarded the provider routes while `presentBucket`
returned the containing bucket document whole. Adding `signingKey` reproduced that bug exactly unless both
were done together — and they were, because `presentBucket` now *delegates* to `presentAll` rather than
repeating the rule. Anything new that returns a bucket must come through there too.

### A PEM needle never matches a JSON leak

The MCP secrecy sweep searches serialised responses for a literal secret. A stored key is PEM, so a leak
through a JSON response arrives with its newlines escaped — a needle containing real newlines would never
match, and **the assertion would pass while the key was on the wire**. The sweep uses one newline-free
base64 line instead.

### The fixed-origin stubs cannot follow the one-origin-per-case rule

`idp_stub.ts` demands a distinct origin per case, because the discovery and key-set caches are keyed by
URL and a reused origin makes a *later* case fail. These three providers have real, fixed origins. So
`test/federation/recognised_stubs.ts` satisfies the rule the other two available ways: `forgetDiscovery()`
per stub, and advertising the key set at a per-case URL, since jose's `RemoteJWKSet` is held per
`jwks_uri` and nothing resets it.

## Related

- [[upstream-federation]] — the three hops, the decision ladder, and the catalogue this extends.
- [[interaction-page-families]] — the login page's two families and the hydration contract its buttons
  satisfy.
- [[admin-mcp-control-plane]] — the agent surface these providers reached with no new tool.

Verified against [[oauth-server-codebase]] as changed by `specs/053-apple-microsoft-github`.
