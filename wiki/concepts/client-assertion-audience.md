---
type: concept
title: "Client-assertion audience: the lenient rule, the issuer-only rule, and when the default flips"
tags: [oauth, oidc, config, contract]
sources: [oauth-server-codebase]
created: 2026-10-22
updated: 2026-10-22
graph:
  node_type: concept
  relationships:
    - predicate: complements
      object: concept:enterprise-managed-authorization
      source: oauth-server-codebase
      evidence: "const RESERVED_TYPES = new Set([...RESERVED_JWT_TYPES].filter((type) => type !== ID_JAG_JWT_TYPE))"
      confidence: high
      status: current
---

# Client-assertion audience

A client that authenticates with a signed JWT (`private_key_jwt`, `client_secret_jwt`) names, in `aud`,
the authorization server it wrote the assertion for. Which values this server accepts there is decided in
one place, `tokenJwtAuth` (`lib/shared/token_jwt_auth.ts:127-149`), for all six endpoints that take client
authentication: token, introspection, revocation, PAR, device authorization and CIBA. Spec 111 (2026-10-22)
made the rule a setting.

## The two rules

| `aud` | Lenient (default) | Issuer-only (`clientAuth.issuerOnlyAudience`) | FAPI on |
| --- | --- | --- | --- |
| the issuer, as a string | accepted | accepted | accepted |
| `[issuer]` | accepted | accepted | refused |
| the token endpoint URL | accepted | refused | refused |
| the URL of the endpoint receiving it | accepted | refused | refused |
| `[issuer, anything]` | accepted | refused | refused |
| another issuer, the root at a project | refused | refused | refused |

"The issuer" is the addressed project's (`issuerFor(oidc.bucket)`), never the instance's. Comparison is
exact string comparison, so a trailing slash is a different value.

**Issuer-only** is draft-ietf-oauth-rfc7523bis §4 item 3b and §5: the issuer identifier "as its sole value",
and the token endpoint URL "MUST NOT be used". It answers the audience-injection attack (CVE-2025-27370,
CVE-2025-27371): a malicious authorization server gets a client to write an assertion audienced at *this*
server's token endpoint, then spends it here. OpenID Connect Core errata set 3 (draft 36) §9 makes the same
change. Both texts let a server accept a one-element array (rfc7523bis's -03 change log: "Do not restrict
the "aud" claim's type"; Core errata 3 binds only the *client* to a string). FAPI 2.0 §5.3.2.1 cl. 8 and
§5.3.3.1 cl. 5 are stricter — a string, not an array — and `fapi.enabled` implies the issuer-only rule and
adds that (`token_jwt_auth.ts:127-132`). IPSIE SL1 repeats the FAPI wording.

**Lenient** is the default because two texts still in force require more: RFC 9126 §2 ("MUST accept its
issuer identifier, token endpoint URL, or pushed authorization request endpoint URL") and CIBA Core §7.1
(the same, with the Backchannel Authentication Endpoint URL). rfc7523bis updates RFC 9126 but not CIBA; the
OpenID Foundation listed CIBA errata as in progress (April 2025) and none was published by 2026-10-22. So
issuer-only, while opt-in, is the constitution's isolated deviation from two texts, justified inline.

## When the default flips

Tracked in issue #80.

rfc7523bis was approved by the IESG on 2026-04-30 and has sat in RFC Editor final review since
(2026-10-19: "Blocked: Final Approval Pending"). **When it is published as an RFC, the default of
`clientAuth.issuerOnlyAudience` (`lib/configs/application.ts:228`) becomes `true`.** One key covers both
states: after the flip, `false` is the compatibility setting for clients that cannot yet change, and a
stored `false` stays an operator's explicit choice — nothing to migrate. Before flipping, re-read the
published RFC (only editorial change is expected from -11), and the state of the CIBA and OIDC Core errata:
if CIBA is still unchanged, the flip keeps departing from §7.1 and the comments must say so.

The catalog description (`lib/admin/settings/catalog.ts:320`) tells an operator which clients break when
it is turned on: any that put the token endpoint URL, another endpoint's URL, or several values in `aud`.

## The lenient rule's third value is a path

The endpoint-URL value is `issuer + endpointPath(oidc.route)` (`token_jwt_auth.ts:52-57`). A context built
by the auth plugin carries the matched path; one built directly carries a route *name*. Before spec 111 the
name was glued onto the issuer, so CIBA accepted `<issuer>backchannel_authentication` and device
authorization `<issuer>anonymous` — no URL of this server — and refused their real URLs, contrary to CIBA
§7.1. `endpointPath` maps a name through `routeNames`; device authorization now passes its name
(`lib/actions/authorization/device.ts:143`). CIBA's route must stay the name `backchannel_authentication`:
`lib/addon/claims.ts`, `check_openid_scope.ts` and `process_request_object.ts` branch on it.

## Explicit typing

A client assertion typed for another job is refused under either rule
(`token_jwt_auth.ts:87-101`): every member of `RESERVED_JWT_TYPES` (`lib/consts/jwt_types.ts:12`) except
`client-authentication+jwt`. An untyped assertion is accepted — rfc7523bis §4 (new RFC 7523 §3.2) makes
typing a client SHOULD and refusing untyped ones NOT RECOMMENDED. The same set, minus the ID-JAG type that is
that grant's own profile, is what the JWT-bearer grant refuses (`lib/assertions/verify.ts:56`), so a type
added later reaches both surfaces (RFC 8725 §3.11). `soleAudience` and `normalisedType` are one shared copy
in `lib/helpers/jwt.ts:36-49`.

## Not touched

- The audience of a JWT used as an authorization grant (rfc7523bis §4 item 3a: issuer *or* token endpoint
  URL) — see [[enterprise-managed-authorization]].
- Request Objects, checked 2026-10-23. Every final text allows more than the issuer alone. OIDC Core errata set 2
  §6.1 says "SHOULD be or include". RFC 9101 §4 says "should be". FAPI 2.0 Message Signing (final, 2025-09-25)
  §5.3.1 item 2 says the server requires `aud` "to be, or to be an array containing" the issuer.
  `processRequestObject` accepts any `aud` containing the issuer, which matches all three. Only OIDC Core
  errata 3, still draft 36, tightens it ("MUST be the OP's Issuer Identifier … as a string"). Tightening now
  would depart even from FAPI, so it waits for that errata's approval, tracked with the default flip in
  issue #80.
- This server sends no client assertion of its own (upstream federation authenticates with a secret), so the
  client-side half of rfc7523bis needs nothing.
