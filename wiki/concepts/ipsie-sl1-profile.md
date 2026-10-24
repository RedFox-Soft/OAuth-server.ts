---
type: concept
title: "The IPSIE SL1 profile switch: what it enforces, what it needs, what it leaves out"
tags: [oauth, oidc, config, contract, security]
sources: [oauth-server-codebase]
created: 2026-10-23
updated: 2026-10-23
graph:
  node_type: concept
  relationships:
    - predicate: extends
      object: concept:session-expiry-claim
      source: oauth-server-codebase
      evidence: "export function sl1(): boolean { return ApplicationConfig['ipsieSl1.enabled']; }"
      confidence: high
      status: current
    - predicate: complements
      object: concept:client-assertion-audience
      source: oauth-server-codebase
      evidence: "if (config['fapi.enabled'] || sl1()) {"
      confidence: high
      status: current
---

# The IPSIE SL1 profile switch

`ipsieSl1.enabled` (off by default) applies the OpenID Provider rules of the IPSIE SL1 OpenID Connect Profile
(`draft-openid-ipsie-sl1-profile`, editor's draft of 2026-09-29) and the IPSIE Common Requirements Profile it points
to (`draft-ipsie-common-requirements-profile` -00). Spec 112 (2026-10-23).

Every rule here departs from a text the server otherwise follows, so none can be a default. That is why they sit
behind one named switch (constitution, Principle I):
- RFC 8252 §7.3 asks for loopback `http` redirects for native apps;
- MCP Authorization keeps open registration and metadata-document clients;
- OIDC Core §3.1.2.1 makes `acr_values` voluntary;
- OIDC Registration defaults to RS256.

The SL1 rules the server already meets without a switch are listed in [[session-expiry-claim]].

Every rule reads the setting where it is enforced, through `sl1()` (`lib/sl1/rules.ts:11`), so a grep for `sl1()`
finds them all. Discovery is the one exception: it reads `config['ipsieSl1.enabled']` itself
(`lib/configs/discoverySupport.ts:170`), because a configuration-layer module must not import `lib/sl1/`.

## What it enforces

| Rule | Text | Where |
| --- | --- | --- |
| No `http` redirect URI, loopback included, at `/auth` and at end-session; refused per URI, so a client keeps its `https` ones | SL1 §3.2.1 | `lib/models/client/checks.ts:79` |
| A write that adds what the profile forbids is refused, naming the attribute and the section | SL1 §3.2.1, CR §3.3 | `lib/models/client/register.ts:97` |
| A URL `client_id` is served only from a stored record; no document is fetched | SL1 §3.2.1, CIMD §7.2 | `lib/client_metadata_document/resolve.ts:30` |
| `response_type` must be `code` (`unsupported_response_type`) | SL1 §3.2.1 | `lib/actions/authorization/check_response_type.ts:21` |
| Every token request needs a DPoP proof, at every grant (`invalid_dpop_proof`); a certificate-bound client is refused | SL1 §3.2.1 (SHOULD) | `lib/actions/token.ts:93` |
| A public client's refresh token without `jkt` is refused | RFC 9449 §5 | `lib/shared/refresh_token_validation.ts:137` |
| A client registered for an algorithm outside PS256/ES256/EdDSA, or for `client_secret_jwt`, resolves as unknown (`invalid_client`) | CR §3.3 | `lib/models/client/validate.ts:188` |
| A signed response with no registered algorithm, or with the RS256 default a save wrote, is signed for PS256, written into the record when it is next saved; registering RS256 afresh is refused | CR §3.3 | `lib/models/client/schema.ts`, `lib/models/client/register.ts` |
| JWT access tokens and ID-JAGs default to PS256 | CR §3.3 | `lib/models/formats/jwt.ts:27`, `lib/assertions/id_jag.ts:48` |
| Client-assertion and request-object algorithms narrow to the SL1 set at request time | CR §3.3 | `lib/sl1/rules.ts:150` |
| The client-assertion `aud` must be the issuer, as a string (FAPI's rule) | SL1 §3.2.1 | `lib/shared/token_jwt_auth.ts:129` |
| `acr_values` binds: an unsatisfied request ends in `unmet_authentication_requirements` (CIBA: `transaction_failed`) | SL1 §3.2.1 | `lib/helpers/interaction_policy/prompts/login.ts:204`, `lib/actions/authorization/backchannel_result.ts:61` |
| Discovery advertises only what is accepted: SL1 algorithms, `code`, no `client_secret_jwt`, no metadata-document support | OIDC Discovery | `lib/configs/discoverySupport.ts:170` |

**Why the schema keeps the full algorithm lists.** The value sets a stored client is validated against are not narrowed.
The schema re-validates every stored client on each resolution, so narrowing them would have three costs:
- an RS256 client would fail with a generic metadata error instead of being refused by name;
- registration would fail on the enum before it could cite CR §3.3;
- readiness, which validates records, could no longer list such a client.

Only the advertised lists and the lists a request is checked against narrow.

**A stored RS256 is the default, not a choice.** Every save writes the validated record with its defaults
(`toStored`), so nearly every application created through the console or registration holds
`id_token_signed_response_alg: RS256` whether anyone chose it or not. Treating that as a registered algorithm refused
almost every existing client at use; the suite missed it because its seeded records carry no defaults, and the manual
walk on a real database found it. So in the three RS256-defaulted attributes a stored RS256 is served as PS256 and
listed as `default_algorithm`, and the write refuses RS256 only when it adds or changes it.

**The `acr` ladder.** A multi-factor sign-in here is the password plus a second factor, so it satisfies a request for the
password class (`satisfiesAcr`, `lib/sl1/rules.ts:163`). A federated sign-in satisfies only the federated class. Keycloak
(levels of assurance) and Okta (`urn:okta:loa:*`) order classes the same way. The existing essential-`acr` checks
compare exactly and are untouched, so a server with the profile off answers as before.

## What turning it on needs

The settings it needs are one table, `SL1_SETTING_PREREQUISITES` (`lib/configs/configuration.ts:713`):
- `registration.enabled` must be off, or have an initial access token;
- `dpop.enabled` on;
- `pkce.required` on;
- `encryption.enabled` on;
- `par.allowUnregisteredRedirectUris` off.

The last one matters because that PAR branch validates a URI the per-request `http` rule never sees.

`checkIpsieSl1` (`:752`) refuses a configuration that breaks one. That covers the reverse order too (turning DPoP off
while the profile is on), and it holds at boot.

Every issuer must hold a PS256 signing key: the root, and each project with an address of its own. The validator cannot
check this, because it reads no data, so the settings route checks it when the switch turns on
(`lib/admin/settings/routes.ts:246`). PS256 rather than "any SL1 algorithm", because PS256 is the default a client with
no algorithm is given, and the signer is chosen by algorithm.

A project created while the profile is on gets a PS256 signer beside its first RS256 key
(`lib/keys/issuer_keys.ts:142`).

Turning the profile on never changes a stored setting or record by itself.

## Readiness

`GET /admin/api/settings/ipsie-sl1/readiness` (`lib/admin/settings/routes.ts:207`, MCP
`settings_ipsie_profile_readiness_get`, console card on the request-security pane) answers without enabling anything:
- the unmet settings;
- the issuers without a PS256 signer;
- every client the profile would refuse or change, each with its rule codes from `sl1ClientViolations`
  (`lib/sl1/rules.ts:72`).

`default_algorithm` marks a client that registered no algorithm and will be signed for PS256.

A client registered dynamically at the root belongs to no project. The store keeps no index of such clients, so
readiness does not list them, but the profile still refuses them at use.

## Who is outside the client rules

`sl1Exempt` (`lib/sl1/rules.ts:28`):
- **The administrators' project.** It holds the console and the administrators' MCP client. That client's loopback
  `http` redirect serves an agent on the operator's machine.
- **A project's account page.** It asks `/auth` with `response_type=none` and never receives a token.
- **A SCIM connection's client.** Its token reaches only the SCIM endpoint, which SL1 does not govern, and directory
  services hold no DPoP keys.

The PS256 default still applies to all three, and the console verifies its own ID tokens in the algorithm its client
resolves to (`lib/admin/auth/verifyIdToken.ts:101`).

Administrators always see a refused client. The console, the agent and the federation and outside-server
configuration read records with `tryFindClient(id, { administering: true })` (`lib/models/client/validate.ts:120`), so
a profile that refuses a client at use never hides it from the person who has to put it right.

## Always on, whatever the profile

An RSA key shorter than 2048 bits is refused in a client's key set, on registration, edit and `jwks_uri` fetch
(`lib/models/client/keystore.ts:121`), and among the server's own keys (`lib/configs/verifyJWKs.ts:148`). RFC 7518 §3.3
already requires it, and jose already refused to verify with such a key, so this only moves the failure to where the
key is registered.

Administrators can pre-register a Client Identifier URL (CIMD §7.2): `clientIdentifierUrl` on application create
(`lib/admin/clients/routes.ts:126`). It is the only way a URL client exists under the profile.

## What SL1 still needs

- **Request-driven step-up.** SL1 says the provider "MUST be able to satisfy" a request for a multi-factor class. Today
  that is satisfied only in a project that demands a second factor; elsewhere the request ends in the error. This is the
  next feature.
- **`amr` after a federated sign-in** ([[amr-reporting]]).
- **JWTs from other issuers** keep today's algorithms: upstream ID and logout tokens, ID-JAGs and jwt-bearer assertions
  from trusted issuers, and upstream security events. CR §3.3 binds them too, but refusing RS256 there breaks federation
  with providers that sign nothing else. They belong with the relying-party requirements of the federated-`amr` work.
- **TLS versions, cipher suites and DNSSEC** (CR §3.2) are the deployment's, terminated at its proxy.

Constitution 3.2.0 amended Principle VI for this feature: "RS256 when it registered none, or the default a named
profile setting declares while that profile is on".
