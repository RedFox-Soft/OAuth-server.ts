---
type: concept
title: 'SCIM provisioning: connections, /Users, and the sign-in they feed'
tags: [architecture, contract, gotcha, oauth, config]
sources: [oauth-server-codebase]
created: 2026-10-06
updated: 2026-10-15
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
provisions a project's end users over SCIM 2.0 through a **provisioning connection**, and those users sign in
through the same directory by federation. Part 1 ([[end-user-lifecycle]]) built the record and the
access-ending operation this calls; part 3 ([[project-groups]], spec 071) adds `/Groups` — SCIM Groups are a
project's groups of end users — and the `groups` claim, part 4 (split by the owner on 2026-10-07 into several
specs) starts with spec 072: the mass-deprovisioning guard below and [[global-token-revocation]].

## A connection is its own record, bound to one provider

`provisioningConnections` (`lib/consts/storage_inventory.ts:142`, `:512`) holds one document per connection:
its project, one of that project's federation providers, a correlation rule, an email trust policy and its
credentials. Its `_id` is what an end user's `provisionedBy` holds. It is **not** embedded in the project
(`UserBucket`) document like `federation[]`, for the reason [[upstream-federation]] records: a nested secret
leaked for a year because the containing entity's reads skipped the nested entity's presenter. `providerKey`
(`bucketId:providerId`) is a unique index, so one provider binds to at most one connection without a route
having to remember it.

Creating a connection writes `existing_only` to its provider (`lib/provisioning/service.ts:95`): a first
sign-in creating an account would race the directory's own create and leave two accounts for one person.
While bound, the provider can be neither deleted nor switched back to `jit` (409). Deleting a connection is
refused while it manages anyone (`:190`) — deleting people must never be a side effect of deleting
configuration — and the console offers disable instead.

## Credentials: a client that is never stored

The key and secret credentials authenticate at the **project's own token endpoint** as the OAuth client
`scim-<connectionId>`, which is **synthesized from the connection on every resolution and stored nowhere**
(`lib/provisioning/client.ts:31`, consulted after the adapter read at `lib/models/client/validate.ts:132`).
That one decision buys the whole token endpoint for free — `private_key_jwt` with `jti` replay protection,
constant-time comparison, the client-credentials grant — and keeps the connection the single source of its
credential: rotation is one write, and there is no hidden stored client to keep in step or orphan.

**Replacing a secret or a static token is no longer an outage** (since spec 088). Until then the new value
killed the old one in the same write, and Entra quarantines a provisioning job on an invalid credential. Now the
replaced value keeps working until the directory has used the new one and has not used the old one for an hour,
and at most 24 hours. A key credential, or a change of kind, still replaces at once. The rule, the
`credentialRef` on tokens that lets an administrator stop only the old value's tokens, and the static token's
new lifetime are in [[scim-credential-overlap]].

- **The secret is a digest.** The synthesized client carries `clientSecretDigest` and no `clientSecret`;
  comparison hashes what is presented (`lib/models/client/secret.ts:45`; since spec 088 against the overlapping
  previous digest too). Ordinary clients still store the
  plaintext, because `client_secret_jwt` and the symmetric keys derive from it — a standing gap against the
  constitution's "client secrets MUST be stored hashed" that this change did not widen.
- **Basic and post alike** for a connection's secret (`lib/shared/token_auth.ts:170`): Entra lets its
  administrator choose either, and a wrong guess surfaces as `invalid_client` on the customer's "Test
  connection". Not both at once: a request carrying the secret in the header and the body is refused as
  `invalid_request` (`lib/shared/token_auth.ts:84`, RFC 6749 §2.3), so Entra's "How credentials are sent" must be
  Header or Body, never Both — one of the pitfalls the directory guidance below carries (since spec 088).
- **No `scope` in the client metadata.** Client metadata may name only scopes the server advertises, and
  `scim` belongs to a project's SCIM resource, not to the server. That such a client gets `scim` and nothing
  else is enforced at the grant (`lib/actions/grants/client_credentials.ts:41`): absent scope means `scim`, any
  other scope is `invalid_scope`.
- **A static token** is `scimst_` + 256 random bits, stored as
  a SHA-256 digest and found by a point read. The prefix makes it distinguishable from an access token without
  a lookup, lets Okta's header mode send it with no `Bearer` (`lib/scim/principal.ts:63`), and lets a secret
  scanner recognise one. It used to be justified as what Okta needs because "Okta cannot use client credentials
  for SCIM"; the standards review of spec 088 found that out of date. Okta's help pages now document an OAuth 2
  Client Credentials mode for SCIM (not yet in its developer guide, and not yet verified here against a live Okta
  organisation), so the guidance recommends the client secret for Okta and keeps the static token as the
  fallback for an organisation without that mode. Since spec 088 every static token also expires (90 days or a
  year, RFC 7644 §7.4) — see [[scim-credential-overlap]].

### The token endpoint does not check a client's project

`check_bucket.ts` runs only for the authorization and device flows, and a client-credentials token takes its
project from the address it was requested at. So the SCIM resource is a **built-in arm** in
`getResourceServerInfo` (`lib/addon/resources.ts:88`), placed **before** the MCP arm, and
`assertConnectionMayMint` (`lib/provisioning/token_policy.ts:44`) refuses any client that is not an enabled
connection of the *addressed* project — and refuses a connection's client every other indicator, MCP's
included. Tokens are **opaque** (`:22`): a JWT-format client-credentials token is not stored, so it could not
be revoked when a credential is rotated or a connection deleted.

## The SCIM surface

`lib/scim/` is a protocol plugin, mounted bare and beneath `/:bucket` (`lib/index.ts:215`), so a project's
base URL is `<its issuer>/scim/v2` in every addressing form. It is mounted with **statements of its own after
the app chain**, not as links in it: adding it to the chain tipped TypeScript past its instantiation depth
(TS2589), and typing the plugin `AnyElysia` instead erased the whole app's type and broke every Eden client
in the suite. `.use` mutates, so the routes register identically.

- **Its own errors.** The root handler stands aside for every SCIM route, by route key
  (`lib/shared/authorization_error_handler.ts:340`), so Elysia's own validation and parse failures render in
  SCIM's shape too; the plugin records 5xx itself (`lib/scim/index.ts:200`) — a fourth capture site
  ([[error-store-capture-sites]]). Elysia wraps anything a parse hook throws in a `ParseError`, so the 413
  rides as its `cause`. A path beneath a SCIM base that no route matches (`/Bulk`; `/Groups` before part 3) has no
  route key, so the root handler recognises it by path (`isScimPath`, `lib/consts/scim.ts`) and answers a
  SCIM 404 — only while `scim.enabled` is on; off, it answers as any unserved path, so the surface stays
  unannounced ([[feature-flag-gating]]). Found by Okta's SCIM 2.0 Spec Test on 2026-10-07, whose optional
  `/Groups` probe got a 404 whose body read `server_error`; every unserved path now answers `not_found`.
- **Its own parser.** Elysia dispatches on `contentType.charCodeAt(12)` and leaves `application/scim+json`
  unparsed; the plugin's `onParse` reads both JSON types, caps the body at 256 KiB first, and lets other types
  reach a 415.
- **Its own rate limit.** The per-origin limiter's ordinary class is five requests a second per address;
  IPSIE §4.3 requires 25 per tenant, and Entra and Okta send many tenants' traffic from a few addresses. So
  SCIM routes are `exempt` from it and limited per connection inside the plugin
  (`lib/scim/rate_limit.ts:81`), while a request whose credential fails is charged per origin with the strict
  bounds (`:89`) — the exemption moves the limit, it does not remove it.
- **Its own principal** (`lib/scim/principal.ts:85`): a token's `aud` must equal the addressed project's SCIM
  URL and its `bucketId` the addressed project, which is what keeps project A's token out of project B.
- **Its own words.** Since spec 100 its schema and resource-type descriptions (`lib/scim/discovery.ts`) and its
  error details (`lib/scim/principal.ts`, `lib/scim/users.ts`) say "project" — e.g. "End users of this project",
  "that email is already taken in this project". The resource names and the protocol are unchanged.

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
(`lib/federation/resolve.ts:213`, `decideCorrelated` at `:154` since spec 088 split the ladder): the connection's rule names a claim of the ID token and a SCIM
attribute (Entra: `oid` ↔ `externalId`, because Entra's `sub` is pairwise; others default to
`preferred_username` ↔ `userName`), and exactly one provisioned user must match. No match is
`not_provisioned`; a match already linked to another subject is `link_conflict` and an event, not a re-link.
Upstream claims are **not** copied onto a provisioned user — its profile belongs to the directory.

Two things this closes beyond email linking: a provisioned user holds no usable password, so in a project with
a password door the email step would have sent them to `password_required`, which they could never complete;
and the existing-link step now uses `canSignIn`, so a locked account is refused there rather than only at the
door after.

## The three deviation settings

Constitution Principle I puts every deviation from a specification behind a named flag. These are the three
that are behaviours; the two that are absences — no `/Bulk`, and the administrator's local lock — cannot be
switched and are documented in `CONFORMANCE.md`. Each carries an operator-facing explanation in the settings
catalog (`lib/admin/settings/catalog.ts`).

- **`scim.secretCredentials`** (on, `lib/configs/application.ts:814`). IPSIE AL SCIM §4.1 and §10 require
  JWT client authentication (RFC 7523 §2.2); a client secret is not that. **On because Entra's OAuth2 Client
  Credentials Grant and Okta's OAuth 2 client-credentials mode both send a secret.** Corrected in spec 088: the
  reason used to read "Entra ID can only send a secret"; Entra also has a Workload Identity Federation mode,
  which signs, and which this server does not support yet (a later part of the series). Off: secret clients stop
  resolving, so their token requests are `invalid_client`, and their tokens are refused at the SCIM principal;
  nothing is deleted.
- **`scim.staticTokens`** (on, `:804`). §4.1 wants a short-lived OAuth token. **On for directories with no OAuth
  option**: an Okta organisation without the client-credentials mode (its HTTP Header mode), and Entra's
  long-lived bearer mode. Corrected in spec 088: the reason used to read "Okta cannot use client credentials for
  SCIM at all". Since that spec a static token is also no longer only an IPSIE departure that lives forever: it
  expires, as RFC 7644 §7.4 requires ([[scim-credential-overlap]]). Off: static tokens are refused; nothing is
  deleted.
- **`scim.strict`** (off, `:817`), inverted — off means tolerant. The interop profile (§6.5.1.1) requires
  refusing a path-less PATCH and unknown attributes, and IPSIE §6.1.2 forbids `password`. **Off because both
  v1 clients would fail strict**: Okta deactivates with a path-less PATCH and sends `password` on every create;
  Entra sends path-less multi-attribute replaces, `"False"`, capitalised operations, `addresses` in its
  default mappings, and the enterprise `manager` as its bare id — `"value": "<id>"` to set it, `""` in a
  `replace` to clear it (`lib/scim/resource.ts`, `lib/scim/patch.ts`; found by Microsoft's SCIM validator on
  2026-10-06, which failed Add/Replace/Remove Manager until then). On: each of those is a 400, and `/ServiceProviderConfig` declares
  `interopProfileConformant` — the only mode in which it does. **One switch rather than one per tolerance**,
  because no partial combination is conformant and the operator's question is a single one: certifying
  against the profiles, or connecting Entra and Okta. RFC 7644 itself permits a path-less `add`/`replace`;
  only the profile forbids it.

`scim.enabled` (off, `:783`) is a capability switch, not a deviation: the surface lets a third party's system
write to end-user accounts. Connections can be prepared while it is off.

### §4.1 contradicts itself

The same section demands "JWT Client Authentication as defined in [RFC7523] section 2.2" and "HTTP Basic …
credentials (e.g., `client_assertion`, `client_secret`) in the HTTP request body is prohibited". RFC 7523 §2.2
carries the assertion in the body (RFC 7521 §4.2) and Basic carries a shared secret, so no client can satisfy
both. The JWT bullet wins: §10 repeats it, and §4.1 carries an editor's note that it "should be expanded".

## Audit by a connection

`recordConnectionAudit` (`lib/admin/audit/record.ts:129`) writes `connection:<id>` as the actor — the
bootstrap's sentinel convention — with `viaSurface: 'scim'` and the project's `ownerGroupId` (its owning
team), so the project's own administrators see it ([[admin-audit-trail]]). SCIM computes the attribute names that change before the
write, so a request asserting what is already stored writes nothing and audits nothing.

## The mass-deprovisioning guard

Spec 072. Part 1 made deprovisioning instant and total, so a wrong scoping rule in Entra or a compromised
directory credential could end a whole project's access — sessions, grants, consents — in minutes. A connection
may carry an optional `threshold` (`count` 1–100,000 within `windowSeconds` 300–604,800; absent by default):
the first deprovisioning beyond it **holds** the connection, and while held every deprovisioning is refused and
everything else keeps flowing. Only an explicit release ends a hold (`releaseConnection`,
`lib/provisioning/service.ts:434`; route `…/provisioning-connections/:connectionId/release`; MCP
`provisioning_connection_release`, **high**). No edit can end one: `hold` is not in the patch type, and removing
the threshold of a held connection is refused 409.

- **What counts.** A PUT or PATCH whose `input.active === false` — which `updateFor` sets only for a real
  active-to-inactive change — and a DELETE of an existing user of the connection. The gate sits in the SCIM
  `record` closures (`lib/scim/users.ts:305`, `:355`), the one point after every refusal and before any write, so a
  refused request applies nothing, including the profile half of a PUT that also deactivates.
- **Exact without a transaction: a ring of slots** (`claimSlot`, `lib/provisioning/deprovision_guard.ts:88`). A
  counter hands each caller a distinct sequence number (`increment`), and the caller takes slot
  `seq mod count` with an insert-if-absent that treats an expired record as free (`create`), held for
  `windowSeconds` (area `DeprovisionSlot`). Both are single atomic writes on all three backends, so at most
  `count` are admitted in any window of that length, even on a standalone `mongod`. It errs only toward
  stopping sooner (a refused claim burns a number; two concurrent deactivations of one user both count). The
  login throttle's counter-and-window pattern was rejected: its own comment admits a burst at the roll resets
  the count. A release or a threshold change moves `tallyEpoch` on, which renames every slot — the old ones expire.
  `database/verify_deprovision_guard.ts` proves it on real databases (MongoDB: 100 concurrent, exactly 10
  admitted, 2026-10-07).
- **One alert per hold.** `holdIfFree` is a conditional write; only the caller told `true` records the hold
  (`provisioning.connection.update`, `attributes: ['hold']`, under the connection) and mails the administrators
  of the owning team (super administrators for `unassigned`), fire-and-forget (`hold`, `deprovision_guard.ts:185`).
  That audit entry follows the write rather than preceding it — the one departure from audit-first, because
  written before, every refused request in a burst would record a hold only one of them set.
- **429 with `Retry-After: 300`** (`deprovision_guard.ts:42`): the only status Okta retries by itself (it turns a
  5xx into a task an administrator retries by hand); Entra escrows any failure and retries it on its own schedule
  (next cycle, then 6, 12, 24 h), and quarantines a job only from ≥5,000 failures above 40 % — or on 401/403/404 at
  any count, which is why none of those is used. A 5xx would also be captured as a defect.
- **An IPSIE departure, isolated by the threshold itself**: a held leaver keeps access until the release.
  Opt-in per connection, documented in `CONFORMANCE.md`.
- **Every refused removal is recorded** (spec 084), so a release is decided knowing whom it removes. Store
  area `provisioningRefusals`, one record per person per tally generation
  (`${connectionId}:${epoch}:${userId}`): operation, first and last attempt, and an attempt count. The count is
  bumped by one upsert on all three backends (`noteRefusal`, `deprovision_guard.ts:145`).
  - **It never changes the answer.** It is written before the 429 on both the already-held and the just-tripped
    paths. A failed write is swallowed into `provisioning.held.refused`, which now carries `userId`,
    `operation` and `failed`.
  - **Reading it.** `GET …/provisioning-connections/:id/hold` (`readHold`, `lib/provisioning/service.ts:496`;
    MCP `provisioning_hold_get`) lists at most 1,000, newest first, with the total. A person deleted since is
    skipped but still counted.
  - **Release clears it.** `releaseConnection` counts it first; the release's audit entry carries
    `cascade: { refusedRemovals: N }`. It then destroys the records as a best effort, after the hold clears. A
    straggler written by a request that raced the release lands in a generation no read returns, because the
    release moved `tallyEpoch` on. Deleting the connection or the project destroys them too.
  - **The area has no owner.** The drift guard allows owners only on model areas, so a person's records are
    not swept when the person is deleted; they leave with the hold.
  - `database/verify_084_refusals.ts` proves the upsert and the reads on real MongoDB and PostgreSQL
    (2026-10-11).
- **The alert links to the connection** (spec 084): `${ISSUER}/admin/projects/<project>/provisioning/<connection>`
  (`deprovision_guard.ts:209`), the page whose hold panel lists the refused removals
  ([[provider-connection-group-pages]]). Before that it linked to the console's front page. Until spec 100 the
  link read `/admin/buckets/…`; emails already sent still carry it, which is why every old `/admin/buckets/…`
  console address 302-redirects to its `/admin/projects/…` page (`REDIRECTS`, `lib/admin/ui/frame/routes.ts:390`).
- **A hold is visible from every page** (spec 088). `GET /admin/api/provisioning-holds`
  (`lib/admin/provisioning/holds.ts:52`; MCP `provisioning_hold_list`) lists the held connections in the projects
  the caller's project list shows, each as `projectId` and `projectName` (named `bucketId`/`bucketName` until
  spec 100), read by the same `visibleBuckets` (`lib/admin/buckets/visible.ts:15`) the list
  uses, so the count never includes a hold the list cannot lead to. Its store read, `listHeld` (all three
  adapters), also replaced `bucketsHolding` in the project list. The console reads it on every change of page and
  shows the number as a badge on Projects (`useHeldConnections`, `lib/admin/ui/pages/Layout.tsx:96`); a project
  row says On hold and links to its oldest held connection (`heldConnectionId`). The count is not added to
  `/admin/api/me`: MCP's `whoami` shares that read, and the console seeds it once and never refetches it.
- Entra's quarantine on 401 is also why a replaced credential now keeps working for a while
  ([[scim-credential-overlap]]).

## Directory guidance lives on the server

Since spec 088. `lib/consts/known_directories.ts` holds, for Microsoft Entra ID, Okta and "another directory",
the facts an administrator needs at the directory's own screen:

- **its field names**, so a value is copied without translating it — Entra: Tenant URL, Token Endpoint, Client
  Identifier, Client Secret; Okta: SCIM connector base URL, Token URL, Client ID, Client Secret, and Authorization
  for its header mode;
- **the recommended credential and a fallback** — Entra: a client secret; Okta: a client secret, with the static
  token as the fallback; another directory: a key, with a secret as the fallback;
- the recommended correlation rule, the setup steps and the known pitfalls (Entra: send the secret in the header
  or the body, never both; leave Scope blank or `scim`).

It is data, not behaviour, like `known_providers.ts`. A connection's optional `directory` only chooses which
entry the console and an agent read, and nothing at runtime branches on it. When it is absent it is inferred: a
Microsoft provider means Entra, anything else the generic entry (`directoryOf`,
`lib/provisioning/service.ts:815`). The guidance is read through `GET …/provisioning-connections/directories`
(`lib/admin/provisioning/routes.ts:101`), with the project's SCIM base URL and token endpoint filled in, and by
MCP `provisioning_directory_list`. A connection whose project has no address of its own, and so no SCIM base
URL, carries the warning `project_unaddressed` (`bucket_unaddressed` until spec 100;
`lib/provisioning/service.ts:851`). It lives on the server rather than in the console because facts only the
console holds are facts an agent never gets — the lesson of the providers' old `PRESETS` map
([[upstream-federation]]). The correlation constants moved to the import-free `lib/consts/correlation_rules.ts`
so the guidance and `lib/provisioning/correlation.ts` share them.

## Gotchas found while building it

- **A cached discovery document leaves an interceptor behind.** A federation spec that expects discovery
  twice for one issuer leaves the second expectation pending; it fails the *next* spec's
  `assertNoPendingInterceptors`, alphabetically `signin.spec.ts`. Register discovery once per issuer.
- **Elysia passes `params` as `undefined`** on a bare route with no path parameter, not `{}`.
- **The MCP layer cannot build a tool input from a union body schema**: `IssueCredentialBody` is one closed
  object with a `kind` literal union, and the service refuses key fields on other kinds.
- **A SCIM create hashed an unusable password each time** — an argon2 hash, ~100 ms of CPU per user, which
  a directory's initial import at the 25 requests a second IPSIE asks for could not have sustained. Since
  2026-10-06 the unusable password is hashed once per process (`lib/helpers/unusable_password.ts`); its
  preimage is still discarded, so sharing it opens nothing. Fifty creates went from ~12 s to ~0.13 s.

## Related

- [[scim-credential-overlap]] — replacing a secret or static token without an outage, and the static token's lifetime.
- [[end-user-lifecycle]] — the record, `provisionedBy`, and the access-ending operation a SCIM deactivation runs.
- [[upstream-federation]] — the ladder the correlation step now ends early for a bound provider.
- [[mcp-server-authorization]] — the other built-in resource arm, and the declared-resource path SCIM sits before.
- [[error-store-capture-sites]] — the fourth capture site.
- [[per-origin-rate-limiting]] — the limiter SCIM routes are exempt from, and why.

Verified against [[oauth-server-codebase]].
