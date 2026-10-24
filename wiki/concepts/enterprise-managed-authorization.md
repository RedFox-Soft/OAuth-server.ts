---
type: concept
title: 'Enterprise-managed authorization (ID-JAG), token exchange and the JWT bearer grant'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-10-21
updated: 2026-10-21
graph:
  node_type: concept
---

# Enterprise-managed authorization (ID-JAG), token exchange and the JWT bearer grant

Spec 108 made a project able to take both roles of MCP enterprise-managed authorization
(`io.modelcontextprotocol/enterprise-managed-authorization`, built on
`draft-ietf-oauth-identity-assertion-authz-grant-04`, "ID-JAG"):

- **Receiving authorization server.** An agent presents an ID-JAG — a short JWT an enterprise identity
  provider signed: "this person, through this agent, may get a token from you for this MCP server" — with
  the JWT bearer grant (RFC 7523 §2.1 as updated by `draft-ietf-oauth-rfc7523bis`), and gets an access
  token for one of the project's declared APIs. No browser, no consent screen, no refresh token.
- **Identity provider.** An application holding a person's ID token or refresh token from the project
  exchanges it (RFC 8693) for an ID-JAG addressed to an outside authorization server the project is
  connected to.

Spec 039 had listed this as a deliberate non-goal ([[mcp-server-authorization]]). The two grants are new:
nothing at `/token` handled `jwt-bearer` or `token-exchange` before; every RFC 7523 mention was client
authentication (`lib/shared/token_auth.ts`).

Both grants are off by default (`jwtBearer.enabled`, `tokenExchange.enabled`) and catalogued as
`experimental` and `risk: 'security'` (`lib/admin/settings/catalog.ts`), because the profile is a draft.

## Where trust lives on the receiving side

On the **sign-in provider**, as two optional fields (`lib/federation/types.ts:104`, `:110`):
`acceptsIdentityAssertions` (ID-JAG) and `plainAssertions` (story 4, below). Not a new record, because the
provider already holds everything an ID-JAG needs — the issuer, the keys (through discovery), the tenant,
and the link from the provider's subject to an end user. ID-JAG §5 says the IdP issues "the same identifier
for the user that it would have included in an ID Token intended for the Resource Authorization Server",
which is exactly the link the provider keeps. A trust is honoured only while the provider is enabled
(`lib/assertions/verify.ts:83`).

Two providers of one project sharing an issuer cannot both be trusted for assertions
(`lib/admin/federation/validate.ts:153`): an assertion names its issuer, never a provider, and two would
leave which link it means a guess. A provider that publishes no keys (a profile-API provider such as
GitHub) cannot be trusted for them at all.

Setting either field through MCP is high-consequence (`highWhenSets` on `federation_provider_create`/
`_update`, `lib/mcp/catalogue.ts`): it lets an outside party mint tokens for the project's people.

## Why a verifier of its own

`lib/assertions/verify.ts:110` does not reuse `authenticateUpstream` (`lib/upstream_signals/assertion.ts`),
although it shares its parts — the presented-JWT key cache, the asymmetric algorithm list (exported for this),
discovery. `authenticateUpstream` finds the provider by `(iss, our client id there)` read from `sub` or `aud`;
an ID-JAG names this server in `aud` and the agent in `client_id`, and a plain assertion names a person in
`sub`. It is also single-use by construction, which an ID-JAG is not (below). A third lookup mode inside the
upstream-signal receiver would have coupled the logout and revocation receivers to grant semantics they do not
share.

What it checks, in order: reserved `typ`s refused (`client-authentication+jwt`, `dpop+jwt`, `at+jwt`,
`logout+jwt`, `secevent+jwt`, …, `:54`) so a JWT written for one job cannot be replayed as a grant; the
project's own issuer refused (`:136`, ID-JAG §9.3); the trusted provider found by exact issuer; signature,
`exp`, `nbf` through jose; `sub`, `jti`, `iat`, a lifetime no longer than `jwtBearer.maxAssertionLifetime`
(RFC 7521 §5.2's "unreasonably far in the future"); then per profile — an ID-JAG's `aud` is the issuer alone,
never the token endpoint (`:194`, ID-JAG §4.4.1), and its `client_id` the authenticated client; a plain
assertion's `aud` is the issuer or the token endpoint URL (7523bis §4 item 3a). The tenant check accepts the
ID-JAG's `tenant` or the provider's own organisation claim (Entra's `tid`) (`:99`).

Every refusal is `invalid_grant` with one description; the reason travels in `error_detail`, which reaches no
response — so a caller cannot learn which issuers a project trusts or whom it knows.

## Re-submittable ID-JAG, single-use plain assertion

ID-JAG §4.4.3: "clients MAY re-submit the original Identity Assertion JWT Authorization Grant to obtain a new
Access Token. The ID-JAG replaces the use of Refresh Token." So an ID-JAG's `jti` is **not** a nonce; replay
by another client is refused by the `client_id` binding, reuse at another server by `aud`. A plain assertion
binds no client, so it is single-use (`ReplayDetection` under `jwtb:<bucket>:<provider>:`, `:219`), spent only
after every other check passed.

## One ladder for who the person is

`lib/assertions/person.ts:18` calls `resolveFederatedAccount` — the browser sign-in's ladder: existing link,
SCIM correlation, trusted email, domains, provisioning, the plan's sign-up limit ([[upstream-federation]]).
Two outcomes a browser can carry on from are refusals here because there is nobody to carry on with: an
address matching a password-only account (the browser asks for that password) and an unverified account in a
project that requires verified email (`:31`).

**Gotcha — `email_verified`.** The ladder links or verifies by email only when the provider is
`emailTrusted` **and** the claims carry `email_verified: true`. An ID-JAG from an IdP that sends `email` alone
cannot link to an existing account by address, and an account it creates is unverified — the answer a
browser sign-in gives for the same claims. The issuing side therefore puts `email_verified: true` next to
`email` (`lib/assertions/id_jag.ts:91`), and includes the address only when it is verified.

## The access token: grant-less, no refresh

`lib/actions/grants/jwt_bearer.ts:202` mints an `AccessToken` with no `grantId`. A Grant per presentation
would leave one orphan record per re-submission, and carry consent semantics the assertion replaces. Nothing
downstream needs one: introspection checks a grant only when present, `revokeAccountAccess` sweeps tokens by
account and client, and `userinfo` refuses a grant-less token with `invalid_token` — correct, since such a
token's audience is an API and its scope never includes `openid`.

The audience is exactly one declared API, chosen from the ID-JAG's `resource` (one URI or several) and the
request's (`:45`). This instance's administrative MCP endpoint and SCIM endpoints are refused by name: no
assertion reaches the administrative or provisioning planes. Scope is the ID-JAG's `scope` ∩ the request's ∩
the API's; named nowhere, nothing is granted (RFC 7521 §4.1), so an API that declares scopes answers
`invalid_scope`. For a plain assertion the ceiling is the provider's trust for that API (`:86`).

The response carries `resource` because ID-JAG §4.4.1 says it "MUST include the granted resource", citing an
RFC 8707 section that defines no response member (`:243`).

DPoP: an ID-JAG with `cnf.jkt` needs a proof by that key; `jwt-dpop` (from the expired
`draft-parecki-oauth-jwt-dpop-grant-01`, which ID-JAG cites normatively) is accepted for bound assertions and
allowed to any client allowed `jwt-bearer` (`lib/models/client/checks.ts:39`).

Monthly activity counts the person as a `federated` sign-in, read off the grant type
(`lib/activity/note.ts:91`).

## The issuing side

`lib/actions/grants/token_exchange.ts:20` implements only the ID-JAG profile of RFC 8693. `actor_token` is
refused (`:38`): ID-JAG defines no processing for it and RFC 8693 §2.1 requires one to be validated. Error
codes follow RFC 8693 §2.2.2 — an invalid or unacceptable subject token is `invalid_request` ("MUST"), a target
the project will not vouch to `invalid_target` — rather than ID-JAG's non-normative `invalid_grant` example.

**Subject tokens** (`lib/assertions/subject_token.ts:112`): an ID token the project issued to the asking
application, checked with expiry by `IdToken.verifyFresh` (`lib/models/id_token.ts:302`; `validate` ignores
expiry because hints may be stale) and typed `JWT` or untyped, so a logout token or introspection response
signed by the same keys for the same audience is not accepted; or a refresh token, validated by the code the
refresh grant uses (`lib/shared/refresh_token_validation.ts:50`), never consumed or rotated. Presenting a
rotated-away refresh token revokes the grant there too (`:40`).

**Gotcha — pairwise applications.** An ID token issued to an application with pairwise subjects is refused
with a description telling it to use its refresh token (`lib/assertions/subject_token.ts:47`): a pairwise
`sub` is a one-way digest and nothing maps it back — sessions are not indexed by the ID token's `sid`. This
narrows ID-JAG §4.3's "MUST accept Identity Assertions" for that kind of application, deliberately; a reverse
index would add a write to every sign-in.

**Outside authorization server connections** are their own store area (`outsideAuthorizationServers`,
`lib/consts/storage_inventory.ts:641`), not part of the bucket document — that would put them in the
whole-array replace race federation providers live with. The `_id` is a digest of (project, issuer), so one
connection per issuer per project is the primary key. A connection says which applications may ask (each
with its client id there unless its own is a URL — ID-JAG §5's shared namespace), and rules of who —
everyone, or members of project groups (MCP-EMA §7.2's example) — may get which MCP servers and scopes there
(`lib/assertions/policy.ts:34`). A rule naming a group deleted since matches nobody; nothing points back to a
group, so the deletion cannot cascade, and silently widening the rule would be the wrong failure. Connections
cannot point at the project's own issuer, the administrative MCP endpoint or a SCIM endpoint
(`lib/admin/outside-servers/service.ts:55`), and an update cannot change the issuer.

The ID-JAG's `sub` is what an ID token issued to the connection's named sign-in application would carry —
pairwise where that application is — else the account id (`lib/assertions/id_jag.ts:27`). It is signed with
the project's own keys, RS256 where the project holds an RSA key, since the outside server registered no
algorithm (`:43`), and PS256 while the IPSIE SL1 profile is on (spec 112, [[ipsie-sl1-profile]]). Issuing an ID-JAG counts no monthly activity: no token for this project's resources is
issued.

## Deliberately stricter than MCP-EMA

MCP-EMA lets a client known by its metadata document present an ID-JAG without authenticating (§5) and
requires client authentication at the exchange only "if the IdP requires client authentication" for sign-in
(§4). Both grants here refuse a client that does not authenticate (`unauthorized_client`): ID-JAG §9.1 says the
profile "SHOULD only be supported for confidential clients", and without authentication the `client_id`
binding binds nothing. An MCP client that is public on either side cannot use the feature.

## Not done

General token exchange of access tokens (delegation, `act`/`may_act`); SAML subject tokens and `sub_id`;
`authorization_details`; step-up; protected issuer-acceptance discovery (ID-JAG §9.4 MAY); resolving a person
by `aud_sub`; workload identity federation as Entra and GitHub practise it, which is federated *client
authentication*, not this grant (RFC 7523 §3 item 2B requires such a JWT's `sub` to be the client id).

7523bis's tightened client-authentication audience was listed here until spec 111 (2026-10-22), which made it
an opt-in setting, `clientAuth.issuerOnlyAudience`, off until the RFC is published — see
[[client-assertion-audience]].

The two-project flow on one instance (spec story 3) is not covered by `bun test`: discovery of a provider
requires https and an issuer that matches, and the test instance's `ISSUER` is `http://e.ly`. Resolving a
same-instance project's keys in-process would have created the instance-specific path the spec rules out.
