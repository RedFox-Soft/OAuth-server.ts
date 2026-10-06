---
type: concept
title: 'SCIM provisioning: connections, /Users, and the sign-in they feed'
tags: [architecture, contract, gotcha, oauth, config]
sources: [oauth-server-codebase]
created: 2026-10-06
updated: 2026-10-06
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:end-user-lifecycle
    - predicate: depends_on
      object: concept:upstream-federation
    - predicate: depends_on
      object: concept:mcp-server-authorization
---

# SCIM provisioning: connections, /Users, and the sign-in they feed

Spec 070 — part 2 of 4 of the SCIM series (issue #62). An enterprise directory (Microsoft Entra ID, Okta)
provisions a bucket's end users over SCIM 2.0 through a **provisioning connection**, and those users sign in
through the same directory by federation. Part 1 ([[end-user-lifecycle]]) built the record and the
access-ending operation this calls; part 3 adds groups, part 4 shared signals and `/Bulk`.

## A connection is its own record, bound to one provider

`provisioningConnections` (`lib/consts/storage_inventory.ts:141`, `:512`) holds one document per connection:
its bucket, one of that bucket's federation providers, a correlation rule, an email trust policy and its
credentials. Its `_id` is what an end user's `provisionedBy` holds. It is **not** embedded in the bucket
document like `federation[]`, for the reason [[upstream-federation]] records: a nested secret leaked for a
year because the containing entity's reads skipped the nested entity's presenter. `providerKey`
(`bucketId:providerId`) is a unique index, so one provider binds to at most one connection without a route
having to remember it.

Creating a connection writes `existing_only` to its provider (`lib/provisioning/service.ts:95`): a first
sign-in creating an account would race the directory's own create and leave two accounts for one person.
While bound, the provider can be neither deleted nor switched back to `jit` (409). Deleting a connection is
refused while it manages anyone (`:190`) — deleting people must never be a side effect of deleting
configuration — and the console offers disable instead.

## Credentials: a client that is never stored

The key and secret credentials authenticate at the **bucket's own token endpoint** as the OAuth client
`scim-<connectionId>`, which is **synthesized from the connection on every resolution and stored nowhere**
(`lib/provisioning/client.ts:31`, consulted after the adapter read at `lib/models/client/validate.ts:123`).
That one decision buys the whole token endpoint for free — `private_key_jwt` with `jti` replay protection,
constant-time comparison, the client-credentials grant — and keeps the connection the single source of its
credential: rotation is one write, and there is no hidden stored client to keep in step or orphan.

- **The secret is a digest.** The synthesized client carries `clientSecretDigest` and no `clientSecret`;
  comparison hashes what is presented (`lib/models/client/secret.ts:51`). Ordinary clients still store the
  plaintext, because `client_secret_jwt` and the symmetric keys derive from it — a standing gap against the
  constitution's "client secrets MUST be stored hashed" that this change did not widen.
- **Basic and post alike** for a connection's secret (`lib/shared/token_auth.ts:169`): Entra lets its
  administrator choose either, and a wrong guess surfaces as `invalid_client` on the customer's "Test
  connection".
- **No `scope` in the client metadata.** Client metadata may name only scopes the server advertises, and
  `scim` belongs to a bucket's SCIM resource, not to the server. That such a client gets `scim` and nothing
  else is enforced at the grant (`lib/actions/grants/client_credentials.ts:41`): absent scope means `scim`, any
  other scope is `invalid_scope`.
- **A static token** (Okta cannot use client credentials for SCIM) is `scimst_` + 256 random bits, stored as
  a SHA-256 digest and found by a point read. The prefix makes it distinguishable from an access token without
  a lookup, lets Okta's header mode send it with no `Bearer` (`lib/scim/principal.ts:63`), and lets a secret
  scanner recognise one.

### The token endpoint does not check a client's bucket

`check_bucket.ts` runs only for the authorization and device flows, and a client-credentials token takes its
bucket from the address it was requested at. So the SCIM resource is a **built-in arm** in
`getResourceServerInfo` (`lib/addon/resources.ts:88`), placed **before** the MCP arm, and
`assertConnectionMayMint` (`lib/provisioning/token_policy.ts:44`) refuses any client that is not an enabled
connection of the *addressed* bucket — and refuses a connection's client every other indicator, MCP's
included. Tokens are **opaque** (`:22`): a JWT-format client-credentials token is not stored, so it could not
be revoked when a credential is rotated or a connection deleted.

## The SCIM surface

`lib/scim/` is a protocol plugin, mounted bare and beneath `/:bucket` (`lib/index.ts:213`), so a bucket's
base URL is `<its issuer>/scim/v2` in every addressing form. It is mounted with **statements of its own after
the app chain**, not as links in it: adding it to the chain tipped TypeScript past its instantiation depth
(TS2589), and typing the plugin `AnyElysia` instead erased the whole app's type and broke every Eden client
in the suite. `.use` mutates, so the routes register identically.

- **Its own errors.** The root handler stands aside for every SCIM route, by route key
  (`lib/shared/authorization_error_handler.ts:340`), so Elysia's own validation and parse failures render in
  SCIM's shape too; the plugin records 5xx itself (`lib/scim/index.ts:200`) — a fourth capture site
  ([[error-store-capture-sites]]). Elysia wraps anything a parse hook throws in a `ParseError`, so the 413
  rides as its `cause`.
- **Its own parser.** Elysia dispatches on `contentType.charCodeAt(12)` and leaves `application/scim+json`
  unparsed; the plugin's `onParse` reads both JSON types, caps the body at 256 KiB first, and lets other types
  reach a 415.
- **Its own rate limit.** The per-origin limiter's ordinary class is five requests a second per address;
  IPSIE §4.3 requires 25 per tenant, and Entra and Okta send many tenants' traffic from a few addresses. So
  SCIM routes are `exempt` from it and limited per connection inside the plugin
  (`lib/scim/rate_limit.ts:81`), while a request whose credential fails is charged per origin with the strict
  bounds (`:89`) — the exemption moves the limit, it does not remove it.
- **Its own principal** (`lib/scim/principal.ts:85`): a token's `aud` must equal the addressed bucket's SCIM
  URL and its `bucketId` the addressed bucket, which is what keeps bucket A's token out of bucket B.

### Own filter parser and patch applier, not the libraries issue #62 named

`scim2-parse-filter` 0.3.0's quoted-string regex backtracks exponentially on an unterminated run of newlines,
reachable from `?filter=`. `scim-patch` 0.9.3 rejects `REPLACE`, throws on a path-less `Remove`, stores
`"False"` as a string, matches names case-sensitively, and had two prototype-pollution advisories in 2026. The
replacements are small because the clients' grammar is: a single-pass tokenizer and an allow-list
(`lib/scim/filter.ts:40`, `:234`) whose output is the store's fixed equality lookup, and an applier that
resolves every path against the declared attribute table in `lib/consts/scim.ts` and refuses `__proto__`,
`constructor` and `prototype` anywhere (`lib/scim/patch.ts:156`, `:425`). A fast-check property holds the
parser to linear time.

## Sign-in: the correlation rule ends the ladder

At a provider bound to a connection, an unlinked sign-in never reaches the email steps
(`lib/federation/resolve.ts:208`, `:142`): the connection's rule names a claim of the ID token and a SCIM
attribute (Entra: `oid` ↔ `externalId`, because Entra's `sub` is pairwise; others default to
`preferred_username` ↔ `userName`), and exactly one provisioned user must match. No match is
`not_provisioned`; a match already linked to another subject is `link_conflict` and an event, not a re-link.
Upstream claims are **not** copied onto a provisioned user — its profile belongs to the directory.

Two things this closes beyond email linking: a provisioned user holds no usable password, so in a bucket with
a password door the email step would have sent them to `password_required`, which they could never complete;
and the existing-link step now uses `canSignIn`, so a locked account is refused there rather than only at the
door after.

## The three deviation settings

Constitution Principle I puts every deviation from a specification behind a named flag. These are the three
that are behaviours; the two that are absences — no `/Bulk`, and the administrator's local lock — cannot be
switched and are documented in `CONFORMANCE.md`. Each carries an operator-facing explanation in the settings
catalog (`lib/admin/settings/catalog.ts`).

- **`scim.secretCredentials`** (on, `lib/configs/application.ts:778`). IPSIE AL SCIM §4.1 and §10 require
  JWT client authentication (RFC 7523 §2.2); a client secret is not that. **On because Entra ID can only send
  a secret** until workload identity federation (part 4). Off: secret clients stop resolving, so their token
  requests are `invalid_client`, and their tokens are refused at the SCIM principal; nothing is deleted.
- **`scim.staticTokens`** (on, `:787`). §4.1 wants a short-lived OAuth token. **On because Okta cannot use
  client credentials for SCIM** at all. Off: static tokens are refused; nothing is deleted.
- **`scim.strict`** (off, `:800`), inverted — off means tolerant. The interop profile (§6.5.1.1) requires
  refusing a path-less PATCH and unknown attributes, and IPSIE §6.1.2 forbids `password`. **Off because both
  v1 clients would fail strict**: Okta deactivates with a path-less PATCH and sends `password` on every create;
  Entra sends path-less multi-attribute replaces, `"False"`, capitalised operations, and `addresses` in its
  default mappings. On: each of those is a 400, and `/ServiceProviderConfig` declares
  `interopProfileConformant` — the only mode in which it does. **One switch rather than one per tolerance**,
  because no partial combination is conformant and the operator's question is a single one: certifying
  against the profiles, or connecting Entra and Okta. RFC 7644 itself permits a path-less `add`/`replace`;
  only the profile forbids it.

`scim.enabled` (off, `:768`) is a capability switch, not a deviation: the surface lets a third party's system
write to end-user accounts. Connections can be prepared while it is off.

### §4.1 contradicts itself

The same section demands "JWT Client Authentication as defined in [RFC7523] section 2.2" and "HTTP Basic …
credentials (e.g., `client_assertion`, `client_secret`) in the HTTP request body is prohibited". RFC 7523 §2.2
carries the assertion in the body (RFC 7521 §4.2) and Basic carries a shared secret, so no client can satisfy
both. The JWT bullet wins: §10 repeats it, and §4.1 carries an editor's note that it "should be expanded".

## Audit by a connection

`recordConnectionAudit` (`lib/admin/audit/record.ts:128`) writes `connection:<id>` as the actor — the
bootstrap's sentinel convention — with `viaSurface: 'scim'` and the bucket's `ownerGroupId`, so the bucket's
own administrators see it ([[admin-audit-trail]]). SCIM computes the attribute names that change before the
write, so a request asserting what is already stored writes nothing and audits nothing.

## Gotchas found while building it

- **A cached discovery document leaves an interceptor behind.** A federation spec that expects discovery
  twice for one issuer leaves the second expectation pending; it fails the *next* spec's
  `assertNoPendingInterceptors`, alphabetically `signin.spec.ts`. Register discovery once per issuer.
- **Elysia passes `params` as `undefined`** on a bare route with no path parameter, not `{}`.
- **The MCP layer cannot build a tool input from a union body schema**: `IssueCredentialBody` is one closed
  object with a `kind` literal union, and the service refuses key fields on other kinds.
- **A SCIM create is slow by design** (it hashes an unusable password), so a property test that creates
  hundreds of users through SCIM exceeds the 20-second bound in `test/preload.ts`; seed through the store when
  the property is about reading.

## Related

- [[end-user-lifecycle]] — the record, `provisionedBy`, and the access-ending operation a SCIM deactivation runs.
- [[upstream-federation]] — the ladder the correlation step now ends early for a bound provider.
- [[mcp-server-authorization]] — the other built-in resource arm, and the declared-resource path SCIM sits before.
- [[error-store-capture-sites]] — the fourth capture site.
- [[per-origin-rate-limiting]] — the limiter SCIM routes are exempt from, and why.

Verified against [[oauth-server-codebase]].
