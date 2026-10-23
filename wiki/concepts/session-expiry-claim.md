---
type: concept
title: "session_expiry: when an application must send the person back (IPSIE SL1)"
tags: [oidc, config, contract]
sources: [oauth-server-codebase]
created: 2026-10-22
updated: 2026-10-22
graph:
  node_type: concept
  relationships:
    - predicate: complements
      object: concept:amr-reporting
      source: oauth-server-codebase
      evidence: "claimsSupported.add('amr'); claimsSupported.add('session_expiry');"
      confidence: high
      status: current
---

# `session_expiry`

Every ID token from the authorization code, refresh token, device code and CIBA grants carries
`session_expiry`: the moment, in epoch seconds, after which the relying party must send the person back
through this server. Spec 111 (2026-10-22). It is the OpenID Provider half of IPSIE SL1, the profile whose
provisioning half is SCIM ([[scim-provisioning]]); this server also honours the claim as a relying party of
an upstream provider.

## What the texts say

- IPSIE SL1 (latest, 2026-09-29), §3.2.1: ID tokens "MUST indicate the expected expiration time of the RP
  session in the `session_expiry` claim as a JSON integer", and "the value MUST NOT be less than 300 seconds
  (5 minutes) after the value of the `iat` claim". SL1 -00 (2025-04-18) had a `session_lifetime` claim in
  seconds instead; the current text replaced it.
- §3.2.2: the RP "MUST re-authenticate the user through the OpenID Provider after the time indicated", "by
  either initiating a new authorization code flow, or by requesting a new ID token using a previously
  obtained refresh token". Re-authentication need not be interactive: SL1 keeps `max_age` for that.
- OpenID Connect Enterprise Extensions 1.0 draft 01 §2.1 defines the claim ("when a session created from the
  ID Token MUST expire") and sets no rule for the OP's value. Its IANA section is "To be completed": the name
  is **not registered** and may still change.

## The value

`max(iat + 300, min(iat + idToken.relyingPartySessionLifetime, end of the browser session))`, computed in
`IdToken.issue('idtoken')` (`lib/models/id_token.ts:119-128`) from the same instant written as `iat`.
Computed in a grant instead, a second boundary between two clocks could put it at `iat + 299`; written
there, after every claim source is merged, no account record or claims request can stand in for it.

The grants pass the inputs (`lib/shared/session_expiry.ts:12`): the setting, and `exp` of the session the
artefact's `sessionUid` names while it still lives. They and not the model read the setting because no
`lib/models/` file imports `configs/application`. CIBA without a session, and an offline refresh token whose
session is gone, get the setting alone — offline access is by definition independent of the session (OIDC
Core §11). Carrying a session end on every artefact, as `authTime` travels, was rejected: four schemas and
five copy sites for a value only meaningful while the session lives.

## The setting

`idToken.relyingPartySessionLifetime`, integer seconds, default 86400 (`lib/configs/application.ts:851`),
bounded 300 to 1 209 600 by `checkSessionExpiry` (`lib/configs/configuration.ts:515`). The floor is SL1's;
the ceiling is `ttl.Session`, because a relying party cannot be promised a session longer than this
server's own. 24 hours is NIST SP 800-63B-4's AAL2 overall reauthentication timeout ("SHOULD be no more
than"). Named for SL1's "RP session" because `idToken.sessionLifetime` reads as this server's own session
lifetime. Instance-wide; per project is a later extension.

## Advertised and protected like `amr`

- In `claims_supported` whatever the stored `claims` setting holds (`configuration.ts:781`,
  `discoverySupport.ts:125`), for the reason [[amr-reporting]] gives: a stored setting replaces the default
  whole.
- In `RESERVED_CLAIMS` (`lib/consts/reserved_claims.ts:29`), so an account cannot store one, **and** dropped
  from stored claims on read (`lib/addon/account.ts:118`), beside `groups`. Reserving stops new writes only:
  a value stored before, or written to the user store directly, would otherwise reach UserInfo through a
  claims request, because the name is now in `claims_supported`. Found in analysis and proved by
  `test/session_expiry/claims_request.spec.ts`, which fails without the drop.
- A protocol claim beside `sid` and `auth_time` in the four hand-kept lists (filter, consent prompt,
  non-rejectable, consent choices), so asking for it never prompts consent.

## Upstream: this server as a relying party

An upstream ID token's `session_expiry` is validated in `verifyIdToken` (`lib/federation/verifyIdToken.ts:248-260`):
absent changes nothing; not a safe integer, or already past beyond clock tolerance, refuses the sign-in
(reason `session_expiry`, the provider error page, 400). A valid value travels with `upstream` from the
callback (`lib/federation/routes.ts:229`) through the handoff, the pending link and `originOf` to
`Session.upstream.sessionExpiry`, and `Session.save` caps the lifetime at it
(`lib/models/session.ts:167-171`). Capping `exp` reuses the only expiry path sessions have: the authorization
endpoint, device verification, logout, session-bound tokens and the ID token's own `session_expiry` all see
the bound without a check of their own. The server keeps no upstream refresh token, so going back means a
new sign-in at the provider. Auth0's "Use ID Token for Session Expiry" is the same idea, opt-in per
connection and failing a sign-in whose provider sends no claim; here a missing claim changes nothing.

## Known SL1 gaps left by spec 111

- OpenID Provider: `amr` after a federated sign-in, where forwarding a trusted provider's methods is
  deferred by decision ([[amr-reporting]]); no `http` redirect URIs; no unauthenticated dynamic
  registration; DPoP-bound access tokens (SHOULD). The last three break RFC 8252 loopback apps and MCP's
  DCR as defaults, so they belong to a profile switch of their own. Closed since: `auth_time` and `acr`
  in every ID token (2026-10-23, [[authentication-context-reporting]]). Already held: 60-second
  authorization codes (`lib/configs/liveTime.ts:49`), and `max_age` and `acr_values` support.
- The admin console is itself a relying party of this server, with an absolute and a sliding expiry of its
  own, and does not read `session_expiry`.
