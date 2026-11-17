---
type: concept
title: "Client-assertion audience: the issuer-only rule RFC 10070 requires, and the lenient compatibility rule"
tags: [oauth, oidc, config, contract]
sources: [oauth-server-codebase]
created: 2026-10-22
updated: 2026-11-17
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
one place, `tokenJwtAuth` (`lib/shared/token_jwt_auth.ts:131-153`), for all six endpoints that take client
authentication: token, introspection, revocation, PAR, device authorization and CIBA. Spec 111 (2026-10-22)
made the rule a setting; RFC 10070's publication (November 2026) made issuer-only its default.

## The two rules

| `aud` | Issuer-only (default, `clientAuth.issuerOnlyAudience`) | Lenient (the setting off) | FAPI or IPSIE SL1 on ([[ipsie-sl1-profile]]) |
| --- | --- | --- | --- |
| the issuer, as a string | accepted | accepted | accepted |
| `[issuer]` | accepted | accepted | refused |
| the token endpoint URL | refused | accepted | refused |
| the URL of the endpoint receiving it | refused | accepted | refused |
| `[issuer, anything]` | refused | accepted | refused |
| another issuer, the root at a project | refused | refused | refused |

"The issuer" is the addressed project's (`issuerFor(oidc.bucket)`), never the instance's. Comparison is
exact string comparison, so a trailing slash is a different value.

**Issuer-only** is RFC 10070 (formerly draft-ietf-oauth-rfc7523bis) §4, new RFC 7523 §3 item 3 for client
authentication, and §5, new RFC 9126 §2: the issuer identifier "as its sole value", the token endpoint URL
"MUST NOT be used", and the server "MUST reject any JWT that does not contain its issuer identifier as its
sole audience value". It answers the audience-injection attack (CVE-2025-27370, CVE-2025-27371): a
malicious authorization server gets a client to write an assertion audienced at *this* server's token
endpoint, then spends it here. RFC 10070 does not restrict the claim's type, so a one-element array is still
one value (rfc7523bis's -03 change log: "Do not restrict the "aud" claim's type"). OpenID Connect Core
errata set 3 (still a draft, draft 36) §9 makes the same change and binds only the *client* to a string.
FAPI 2.0 §5.3.2.1 cl. 8 and §5.3.3.1 cl. 5 are stricter — a string, not an array — and `fapi.enabled`
implies the issuer-only rule and adds that (`token_jwt_auth.ts:131-136`). IPSIE SL1 repeats the FAPI
wording.

**Issuer-only still departs from CIBA Core §7.1**, which RFC 10070 does not update: the OP "MUST accept its
Issuer Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL". CIBA is Final
(2021-09-01) with no errata published as of 2026-11-17. A CIBA client that audiences either URL is refused
with `invalid_client`. That is the constitution's isolated deviation, justified inline
(`token_jwt_auth.ts:109-130`, `lib/configs/application.ts:232-250`).

**Lenient**, the setting off, is the compatibility answer for clients that cannot yet change: it accepts the
values RFC 9126 §2 named before RFC 10070 and CIBA §7.1 still names, and so departs from RFC 10070. The
catalog description (`lib/admin/settings/catalog.ts:333`) says so, and that the attack is open again while
it is off.

## The default flip (2026-11-17)

Planned in spec 111 and tracked in issue #80: rfc7523bis was approved by the IESG on 2026-04-30 and published
as RFC 10070 in November 2026. Its audience rules are unchanged from -11; the only non-editorial difference
seen is the IANA change controller of `private_key_jwt`/`client_secret_jwt` (IESG rather than IETF). The
default of `clientAuth.issuerOnlyAudience` (`lib/configs/application.ts:250`) became `true`.

One key covers both states, so nothing was migrated. The settings PUT stores only the keys whose submitted
value differs from the one in force (`realChanges`, `lib/admin/settings/routes.ts:181`), so an instance that
never touched the setting picks the new default up, and a stored `false` stays an operator's explicit choice.
An instance that saved settings before `realChanges` existed, when the console pinned every key, may still
hold a `false` nobody chose; check the stored overrides when upgrading such an instance.

## The lenient rule's third value is a path

The endpoint-URL value is `issuer + endpointPath(oidc.route)` (`token_jwt_auth.ts:53-58`). A context built
by the auth plugin carries the matched path; one built directly carries a route *name*. Before spec 111 the
name was glued onto the issuer, so CIBA accepted `<issuer>backchannel_authentication` and device
authorization `<issuer>anonymous` — no URL of this server — and refused their real URLs, contrary to CIBA
§7.1. `endpointPath` maps a name through `routeNames`; device authorization now passes its name
(`lib/actions/authorization/device.ts:143`). CIBA's route must stay the name `backchannel_authentication`:
`lib/addon/claims.ts`, `check_openid_scope.ts` and `process_request_object.ts` branch on it.

## Explicit typing

A client assertion typed for another job is refused under either rule
(`token_jwt_auth.ts:88-102`): every member of `RESERVED_JWT_TYPES` (`lib/consts/jwt_types.ts:12`) except
`client-authentication+jwt`. An untyped assertion is accepted — RFC 10070 §4.2 (new RFC 7523 §3.2) makes
typing a client SHOULD and refusing untyped ones NOT RECOMMENDED. The same set, minus the ID-JAG type that is
that grant's own profile, is what the JWT-bearer grant refuses (`lib/assertions/verify.ts:56`), so a type
added later reaches both surfaces (RFC 8725 §3.11). `soleAudience` and `normalisedType` are one shared copy
in `lib/helpers/jwt.ts:36-49`.

## Not touched

- The audience of a JWT used as an authorization grant (RFC 10070 §4, RFC 7523 §3 item 3: issuer *or* token
  endpoint URL) — see [[enterprise-managed-authorization]].
- SAML bearer assertions, which RFC 10070 §3 forbids for client authentication in new applications: this
  server never accepted them.
- Request Objects, checked 2026-10-23. Every final text allows more than the issuer alone. OIDC Core errata set 2
  §6.1 says "SHOULD be or include". RFC 9101 §4 says "should be". FAPI 2.0 Message Signing (final, 2025-09-25)
  §5.3.1 item 2 says the server requires `aud` "to be, or to be an array containing" the issuer.
  `processRequestObject` accepts any `aud` containing the issuer, which matches all three. Only OIDC Core
  errata 3, still draft 36 and unpublished on 2026-11-17, tightens it ("MUST be the OP's Issuer Identifier …
  as a string"). Tightening now would depart even from FAPI, so it waits for that errata's approval, still
  tracked in issue #80.
- This server sends no client assertion of its own (upstream federation authenticates with a secret), so the
  client-side half of RFC 10070 needs nothing.
