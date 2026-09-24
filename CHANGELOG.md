# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Spec numbers refer to the (untracked) `specs/`
directories; open work is tracked as GitHub issues; full retrospectives live in the git history of
the retired `TASKS.md` and in the knowledge base at `wiki/`.

## [Unreleased]

### Fixed

- Device verification refuses a confirmation when the session holds no form secret, instead of
  comparing two absent values as a match; resuming an interaction after an account change re-saves it
  with the same TTL floor the sign-in screens use, so a record about to expire is not left
  non-expiring.
- Host-addressed buckets: a sign-in at the bucket's host wrote a session cookie the host never read
  (so it was forgotten), and authorization responses and tokens named `ISSUER/<id>` instead of the
  bucket's origin its discovery document advertises; `GET /logout` there read the default bucket's
  session. The bucket record now keeps its host, and `/logout` passes the request host. An interaction
  aborted back to the client names the bucket's issuer, not the instance's.
- ID Token claims beside a resource-bound access token: with `conformIdTokenClaims`, the
  authorization-code, device and CIBA grants read the access token's audience off the instance (always
  empty) and so left profile claims to UserInfo even when the access token, bound to a resource server,
  cannot call it; they now read it from the token's payload, as the refresh grant already did.
- CIBA: the `verifyUserCode` addon receives the request's `user_code`; it was handed the login hint
  instead, so a deployment's user-code check never saw the code the client sent.
- request parameters follow their specifications: `ui_locales` and `claims_locales` are one
  space-separated string each (OIDC Core), no longer an array, and `ui_locales` sent twice is refused;
  `registration`, and a disabled `request`/`request_uri`, are refused with the OIDC Core §3.1.2.6 codes
  instead of `not_supported`; several or malformed `resource` values at `/token` are `invalid_target`
  (RFC 8707), not `invalid_request`; a parameter sent twice to `GET /logout` is refused.
- **breaking** — registration read (`GET /reg/:clientId`) no longer accepts the registration access
  token in the query string (RFC 6750 §2.3, OAuth 2.1); send it in the Authorization header.
- token, device authorization and CIBA endpoints answer as RFC 6749 §5.2 says: an unknown `grant_type` is
  `unsupported_grant_type` (was `invalid_request`), and a grant the client is not registered for is
  `unauthorized_client` (was `invalid_request`).
- tokens: a browser application's rotated refresh tokens again expire when their chain's first token
  would have, instead of each rotation granting a fresh lifetime — dead since `54ba556`, masked by the
  equal default grant lifetime. `ttl.*` now take `(token, client)`. Deployments that lengthened a
  lifetime will see older browser chains sign in once more.
- buckets: device authorization and CIBA started at a named bucket now use its verification page,
  session and `iss`, and refuse another bucket's client as `unauthorized_client`; registration there
  returns a management URI beneath it. A `deviceInfo` override now takes effect (the default records the
  caller's address as a string).
- admin: editing a client in the console or through the agent's `client_update` no longer drops every
  attribute the console does not display. A pairwise client stayed pairwise only until its first edit,
  and a client authenticating with a private key could not be edited at all.
- claims: a client requesting `claims.id_token.sub` as a non-object (`true`, a string, a number) now gets a
  code, as for `null`, instead of `server_error`.
- interactions: when a different account signed in during an interaction, confirming the sign-out
  continues it again. The confirmation always answered 400 `could not find logout details`.

### Changed

- types: the typed (Eden) client sees what the endpoints answer — `/token` declares its 400/401 errors and
  one token body, registration and introspection declare their RFC members, the request headers include
  `accept` and `x-client-cert`, and the admin client schema's grant types and auth method are no longer
  `never` (unions built from a mapped array); the interaction pages (`/ui/*`) and discovery declare
  their answers, and every protocol route its 500. No response changes on the wire.
- **breaking** — extension functions, policy checks, registration policies and RAR validators receive
  the request context itself (`issueRefreshToken(oidc, client, code)`, `check: (oidc) => …`), not
  `{ oidc }`. Request-scoped events carry it first; `grant.revoked` is `(oidc?, grantId)` and fires once
  (a partial sign-out emitted it twice), `code_verification.error` is `(oidc, error)`. No shim.
- request context: `OIDCContext` declares what it holds — built from an init object with a required
  `bucket`, typed entities, `oidc.require(name)`. A getter is a guarantee: `oidc.client` and
  `oidc.session` throw when absent (`authenticatedClient` is gone); optional entities are read as
  `oidc.entities.X?`, replacing the `grant`, `account` and `deviceCode` getters. Unread fields removed.
- request context: request parameters are typed from the schemas the endpoints validate against —
  `PipelineParams` for the authorization, device and backchannel pipeline, `TokenParams` for the grant
  handlers — and the type is closed, so TypeScript overrides reading their own extension parameter
  need an explicit widening. `claims` members are `unknown` until read through `claimRequest()`;
  the schema now declares them as records, accepting exactly the same inputs. JavaScript overrides are
  unaffected.
- client: the client's type names its closed value sets (authentication method, CIBA delivery mode,
  signing algorithms) from the lists the configuration check uses, is read-only all the way down to
  match the freeze, and `adapter('Client')` is typed as holding a `StoredClient`.
- client: the validated client has a type that matches it — the attributes a default always fills are
  required, `client_name`, `contacts`, `default_acr_values` and `client_id_issued_at` are declared — and
  the request context carries it typed (`oidc.client`; see the request-context entry above).
- client: a client is written the same way from every surface, through `registerClient`, and its sector
  identifier document is checked there and only there. Resolving a stored client no longer retrieves
  it, so a pairwise client stays usable while its sector host is down; the console, which stored
  without the check, now refuses an edit the document does not cover. A document-described client
  keeps the check on resolution.
- client: a resolved client is frozen data — no methods, no prototype — and is used through functions
  (`redirectUriAllowed(client, uri)`, `clientMetadata(client)`, …). `Client` is an object holding
  `find`/`tryFind`; back-channel logout and CIBA ping moved to `lib/shared/client_notifications.ts`.
- client: a client's key material is derived beside it by `clientKeys(client)` instead of hanging off
  the object, and its key set no longer writes certificate thumbprints onto the client's own keys. The
  `clientAuthMethod` / `clientAuthSigningAlg` aliases are gone; read the registered attribute names.
- client: each registration attribute's validation rules are declared once, in
  `lib/consts/client_attributes.ts`, replacing five parallel lists that nothing kept in step. No
  behaviour change, verified against 33,159 registrations; three rules that could never fire, and one
  check that never ran, are removed.

## [0.5.0] - 2026-09-21

A user bucket finishes becoming a tenant. 0.4.0 gave it a path beneath the server; this release lets
it hold a hostname of its own instead — `acme.auth.example.com` rather than `auth.example.com/acme` —
which is what puts its sign-in cookie on an origin of its own and publishes one metadata location
where a path-bearing issuer forces two. A bucket holds one form of address or the other, never both,
since two addresses would be two issuer identifiers for one population. Changing an address is its
own operation and an administrator of the instance's alone: it names every client that will stop
validating tokens before anything changes, and completes only on a second call.

Signing in to a bucket stops being only a password. Google, Microsoft, Apple and GitHub can each be
connected to a bucket by name, asking only for what that provider actually issues, and the console
now shows the callback address to register — which differs per bucket and appeared nowhere before.
Projects and user buckets can also be deleted from the console, which the management API has always
accepted and nothing in the console reached; a container may take its contents with it, on an
election made separately from confirming, and neither deletion completes by clicking.

**Upgrading signs your administrators in once.** The session cookie is now named after the bucket the
client signs into rather than the address the request arrived at, because the administrators' bucket
and the default one are both served at the root and only the client says which population a sign-in
is for. That is what fixes a console login failing with `interaction session and authentication
session mismatch` whenever the browser already held an end-user sign-in from the same server; the
price is that a console session held from before this release is not read, and the administrator
signs in again. End users are unaffected, no schema migration is declared, and nothing is lost —
accounts, grants, consent and refresh tokens are untouched.

### Added

- A user bucket can be addressed by a hostname of its own rather than a path beneath the server, and
  holds one form or the other — never both, since two addresses would be two issuer identifiers for one
  population. A host isolates the bucket's sign-in cookie by origin, which path addressing cannot do at
  all, and publishes one metadata location instead of the two a path-bearing issuer forces. It costs a
  DNS record and a certificate the operator provides; the console names the record to create and reports
  whether any request has yet arrived, and claims nothing about whether the name resolves. Changing an
  address is its own operation, available only to an administrator of the instance: it names every client
  that will stop validating tokens before anything changes and completes only on a second call. Spec 056.

- site: a blog article can carry inline SVG diagrams. Three colour tokens in the stylesheet make a
  diagram follow the site palette and the reader's theme, and a diagram's labels are left out of the
  page's extracted text, so they neither run together in the Markdown alternate nor get judged as
  prose by the rules that read it. The first article, on DPoP, is rewritten around three of them.
- site: the public site has a blog, and publishing to it is writing one file. The page, the index entry,
  the sitemap entry with its date, the social card, the plain-text alternate, the `llms.txt` entry and
  the feed item are all derived from that file, so nothing is remembered and nothing is half-applied.
  The blog is not exempt from anything: every rule that already fails the build for a marketing page
  fails it for an article, and the rule that catches copy claiming the server stores its data in one
  datastore now reaches articles too — an article genuinely about one backend earns its exemption by
  printing a line telling the reader it is scoped, rather than by being added to a list of excused
  pages. A draft or a future-dated article exists nowhere: no page, no sitemap entry, no feed item, no
  card. Articles are attributed to the project, carry their publication and revision dates where a
  reader can see them, and say so themselves once they are old enough to deserve a second look.

- admin: Microsoft, Apple and GitHub can be connected to a user bucket by name, alongside Google. Each
  asks only for what it actually issues — two values for GitHub, three for Microsoft (including who may
  sign in: one organisation or any Microsoft account, stated with its consequence and not chosen for
  you), four for Apple. Apple needs no client secret: it supplies a signing key and this server produces
  the credential Apple wants on every exchange, so nothing expires and nothing is ever renewed by hand.
  GitHub is not an OpenID Connect provider and asserts no identity, so the signed-in person is read back
  from GitHub — including the primary verified address of an account whose profile hides one, and never
  an unverified one. Each provider gets its own branded button, rendered from an inline mark so loading a
  login page still tells no provider that somebody is there.

- admin: Google can be connected to a user bucket by name. The console now shows what to do at Google,
  links straight to it, and — the part that was missing entirely — the exact callback address to
  register, which differs per bucket and appeared nowhere before; the administrator supplies only the
  client id and secret Google issued. Everything else comes from a recognised-provider catalogue that is
  data, not behaviour: the stored provider is indistinguishable from one configured by hand, so nothing
  can branch on how it was made, and a Google provider configured by hand years ago now renders with its
  own branded button without a migration. The same route serves agents, so an agent connects it the same
  way, with the same checks and one audit entry. A bucket with no slug is told its callback address is
  provisional, because assigning a slug later invalidates it.

- admin: projects and user buckets can be deleted from the console, which was impossible before — the
  management API accepted both deletions and nothing in the console reached them. A container may now
  take its contents with it, a project its OAuth clients and a bucket its end-user accounts, on an
  election the administrator makes separately from confirming; the request carries what they reviewed,
  so a client or account that arrived since is refused rather than destroyed on a stale consent.
  Neither deletion completes by clicking: the administrator types `delete`. A project never reaches
  the bucket it pointed at, under any election, because buckets are shared and hold people no project
  knows about. One deletion writes one audit entry carrying what went by kind and count — replacing
  one entry per withdrawn protected-resource declaration, which a bucket-sized deletion would have
  turned into a trail nobody could read.

### Fixed

- admin: signing in to the console no longer fails with `interaction session and authentication session
mismatch` when the browser already holds an end-user sign-in from the same server, and no longer asks
  for the password on every authorization request. The default bucket and the administrators' bucket are
  both served at the root, so the address alone cannot say which population a sign-in is for — only the
  client can, which is how the rest of the sign-in has always decided it. Naming the session cookie from
  the address meant the authorization request and its resumption read two different cookies and saw two
  different sessions.

- A client can no longer sign an end user out of a user bucket it does not belong to. A sign-out ends
  whatever sign-in the address it was requested at holds, and nothing checked that the client asking
  shared that sign-in — an `id_token_hint` is validated against the issuer, and a bucket served at the
  root shares the server's own, so a token minted for one population could end another's. Buckets that
  share a session cookie still end each other's sign-in, which is what their clients have always done at
  the bare endpoints; anything else is refused.

- admin: two administrators assigning one hostname at the same moment now both get an answer they can
  act on. The route asks the store whether a name is free and writes after the answer, so both reads
  can return "free" and the datastore's own constraint refuses the second write — `UniqueValueTaken`,
  a class introduced precisely so that refusal would be a 409 rather than an internal fault. Nothing
  caught it, on either the create or the address-change route, so the operator who lost the race got a
  500 and a recorded defect. Found by a coverage report rather than by a person: the class was raised
  by all three bucket stores and reached by nothing.

- ci: a commit that touches the PostgreSQL adapter no longer fails the coverage gate for doing so.
  `bun test` runs on the in-memory adapter, so a store's function bodies need a live server and can only
  run under `database/verify_postgres.ts`, which the default run deliberately cannot reach; they report
  4–17% rather than 0% because the import-safety sweep executes their top level and nothing else.
  Seventeen stores and the plumbing they issue SQL through held the project number at 90.92% — which
  Codecov then holds every later commit to — and one duly failed at 84% of a diff whose 62 worst lines
  sat in a single such file. The `codecov.yml` ignore list now names the connection-bound files and only
  those: everything under that directory which runs in process stays measured, because a low number
  there is a real gap, and MongoDB's stores stay measured as well, having no equivalent verification run
  to be judged in instead.

- test: the constant-time comparison cases now judge a timing difference by its size rather than by its
  statistical significance. Welch's t divides by the machine's noise floor, so the 0.1–0.4% residue a
  correct comparison always leaves — where the strings landed, not what the comparison did, as two
  candidates with identical content produce the same spread — scores about three times higher on a
  Linux runner than on the Windows machine whose 100 ns clock the threshold was calibrated against.
  That reddened CI on an unmodified tree, and it meant load made the cases pass while a quiet, precise
  machine failed them. A leak is instead a fraction of the work, and that fraction transfers between
  platforms: 52% on Linux and 59.5% on Windows for a first-difference mutant, against a floor of 2%.

- federation: the authorization code is now bound to the request that asked for it at every recognised
  upstream that supports the binding. Support was read from what a provider publishes, and three of the
  four publish nothing — Microsoft recommends the binding while advertising no method, GitHub has
  supported it since July 2025 while publishing no metadata at all — so those legs were silently going
  without. A provider nobody has vouched for is still judged by its metadata, and nothing is sent where
  support is unknown, because an unrecognised parameter breaks sign-in for everyone.

- admin: an Apple signing key is masked on every read of a provider and of the bucket containing it, the
  same rule the client secret follows and in the same place, so a second credential could not repeat the
  leak the first one had.

- admin: the console's dialogs offered the administrator's own saved credentials. A browser reads an
  address or an identifier sitting beside a password field as a sign-in form, so creating an admin,
  creating an end user, resetting somebody's password and entering an upstream provider's credentials
  were all autofilled from the password store — one distracted confirmation away from creating an
  account with the operator's own email and password, or from overwriting a working provider secret.
- admin: dialogs sat a flat 100px below the top of the window whatever its height, which on a laptop
  is a sixth of the screen and pushed taller dialogs off the bottom. Short viewports now get a small
  offset; large monitors are unchanged.
- interactions: a mistyped password removed the provider buttons from the login page. The refusal
  re-rendered from defaults rather than from the bucket's options, so a page that had just offered a
  federated sign-in came back offering only a password box; the unverified-email refusal did the same.
- admin: the administrators' bucket and the default end-user bucket could be deleted by a super
  administrator while empty. The bucket deletion route does not go through the loader that carries the
  reserved-bucket guard, so it reached no such guard at all; both are now refused before the bucket is
  loaded, whatever is elected and whoever asks.

## [0.4.0] - 2026-09-16

One thing defines this release: a user bucket is a tenant of its own. It is addressed in the URL,
publishes its own metadata, mints tokens carrying itself as `iss`, and holds its own sign-in — so a
browser can be signed in to two buckets at once and neither disturbs the other. The default bucket
keeps the bare issuer and the bare paths, which is what makes the change deliverable to an existing
deployment without a flag day.

Two sign-in defects found on the way are fixed with it, and both had the same shape: a browser rule
no headless test could see. A sign-in that started at a relying party answered `422` for every real
client while the identical URL opened by hand returned `200`, because `SameSite=Strict` withholds a
cookie on exactly the navigation the flow is made of. And the "Remember me" checkbox had never
decided anything.

**Upgrading signs your end users in once.** A session cookie now carries the bucket it belongs to;
one written before this release does not, is never read, and is expired on the first request that
presents it. Nothing is lost — accounts, grants, consent and refresh tokens are untouched — and the
[upgrade guide](https://foxauth.dev/docs/deploy/upgrade/) says what to expect. The admin console
stays at `/admin`.

### Added

- buckets: a user bucket is now a tenant with its own issuer. An operator gives a bucket an address
  and it is served beneath it — `https://auth.example.com/acme` publishes its own metadata at both
  well-known locations a path-bearing issuer has, serves every protocol endpoint, and mints tokens
  carrying itself as `iss`. A client integrates with one exactly as with any authorization server, and
  can finally tell one population's tokens from another's. A client of an addressed bucket is refused
  at any other bucket's address, and a token records which bucket issued it, so a token presented to a
  bucket that did not issue it is reported inactive as RFC 7662 §2.2 requires. **The default bucket is
  unchanged**: it keeps the bare issuer and the bare paths, so nothing integrated before this needs
  reconfiguring and tokens in circulation stay valid. Two reserved buckets — the default one and the
  administrators' — are served at the root by design: they are not addressable and their tokens carry
  the instance's own issuer, which is why the admin console stays at `/admin` and why an agent's
  connection to the administrative MCP plane keeps working. The console's Buckets table reports those
  two as served at the root rather than at the slug they hold, because the Address column is what an
  operator copies when pointing a client at a bucket. A bucket's address is fixed once chosen; renaming would invalidate every
  client integrated with it and wants an operation of its own.

### Fixed

- buckets: a browser can hold a sign-in in more than one user bucket at a time. The session cookie is
  now named after the bucket that wrote it, so two sign-ins are two cookies and neither disturbs the
  other. Before this, signing in to a second bucket overwrote the first bucket's sign-in and the end
  user was silently signed out of an application they had never touched — the buckets were isolated
  from each other, which is what the earlier work proved, but they could not coexist, which nothing
  had checked. A sign-out now ends the sign-in of the bucket its address names and no other, tells no
  other bucket's applications about it, and "Remember me" declined in one bucket says nothing about
  another's lifetime. The administrators bucket is a population like any other here: signing out of
  the console ends its sign-in rather than every sign-in the browser holds. **Everyone signed in when
  this is deployed signs in once more**: the old cookie carried no bucket, is never read, and is
  expired on the first request that presents it.

- buckets: reaching a second user bucket in one browser no longer fails. An authorization request for
  one bucket from a browser signed into another answered `server_error`, leaving the end user with
  nothing to retry: the sign-in check read the account identifier the session happened to carry rather
  than the account that actually resolved, so it suppressed the sign-in prompt for a request that had
  no account at all, and the first consent check to reach inside the absent grant faulted. And where a
  sign-in as the second person did complete, it was read as an account change and answered with a
  sign-out confirmation whose only working button ended every sign-in the browser held — a demand to
  abandon one product in order to use another. A sign-in now records the bucket it belongs to, and
  buckets are compared before account identifiers, because identifiers from two buckets are always
  unequal and say nothing about who is signing in.

- interactions: sign-in works again when it starts at a relying party. The `_interaction` and
  `_session` cookies were written `SameSite=Strict`, which a browser withholds on a
  cross-site-initiated top-level navigation — the shape of the whole flow, since the relying party
  navigates to `/auth`, which sets the cookie and redirects to `/ui/:uid/login`, whose guard requires
  it. Every such sign-in answered `422 Invalid interaction cookie`; opening or reloading the identical
  URL by hand returned 200, because a browser-initiated navigation counts as same-site, which is what
  hid it. `_session` shared the constant and failed more quietly: invisible at `/auth`, an established
  session made a second relying party re-prompt a user who was already signed in. Both are now `Lax`,
  which still withholds them on the cross-site POSTs and subresource requests that carry the CSRF
  property. The admin console's cookie is a separate constant and stays `Strict`.

- admin: a project's assigned user bucket can now be changed and removed. Assigning was one-way — the
  only route took a bucket id and had no value meaning "none" — and the console had no control for it
  at all, so a bucket could be set only through the MCP surface and never unset, however wrong it was.
  The Projects table now has a **Bucket** editor offering the buckets that share the project's owning
  group — the only ones the server will accept — plus "Not set", which is how the default bucket is
  chosen: it belongs to no group, so it is assignable to nothing and needs to be, since a project with
  no bucket already signs its users in from it. Clearing is its own operation on both surfaces
  (`DELETE /admin/api/projects/:id/bucket`,
  published to agents as `project_bucket_clear`). A project with no bucket signs its users in from the
  default bucket, as it always has. Clearing is its own audited action rather than an assignment
  carrying an empty value, because the audit trail records field names and never values: one action
  could not have told an operator which of the two had happened. This also makes the documented
  procedure in "Your first client" true — it described a console control that did not exist.

- admin: the reserved administrators' bucket can no longer be assigned as an ordinary project's user
  bucket. It appeared to be protected by the rule that a project and its bucket share an owning group,
  but that rule did not cover it: the admin bucket sits in the reserved System group, and a super
  administrator whose active scope is empty creates projects into that same group — so the comparison
  was `unassigned` against `unassigned`, which passes. Such a project's end-users were the accounts
  that administer the instance. The route now refuses the reserved bucket outright, the same refusal
  the bucket routes already make.

- mcp: `settings_update` now tells an agent what each server setting accepts. Its published schema
  described no setting at all — the route behind it validates every value in its handler rather than
  in its body schema, so there was nothing there to publish — and a client with no type to check a
  value against sends the text it was handed: `par.enabled: true` arrived as `"true"` and `scopes` as
  one string, both correctly refused, with no encoding available that satisfied caller and server at
  once. Two unrelated clients hit it. Every catalogue key is now published with its type, its allowed
  values where it has them, and a one-line description, all derived from the same catalogue the
  handler enforces. The published schema describes without enforcing, so a setting the catalogue does
  not declare still reaches the handler and is refused by name rather than silently dropped.

- interactions: the "Remember me" checkbox on the sign-in screen now decides how long the sign-in
  lasts. It never had, on any path: the answer was recorded under one name and read under another,
  the answer that was recorded was inverted, nothing anywhere read the resulting flag, and a
  sign-in that asked to be remembered could not clear an earlier decline — four independent breaks
  on one path, each sufficient alone. Declining now yields a session cookie the browser discards
  when it closes; accepting keeps today's behaviour, up to the configured sign-in lifetime. The
  choice survives a one-time-code step, and a path that offers no checkbox — federated sign-in —
  still keeps the sign-in. Nobody who leaves the box ticked sees any change. (spec 049, issue #45)

## [0.3.0] - 2026-09-14

Three things define this release. The server runs on PostgreSQL as well as MongoDB, behind a
schema-migration layer that gates startup on either. The OpenID Foundation conformance suite was run
against it for the first time — twelve plans, 16 680 conditions — and the twelve defects those runs
found are fixed here, from the PAR response's content type to the `code_verifier` alphabet, with
`CONFORMANCE.md` recording where it stands and the five that are still open. And a server setting
now takes effect when it is saved, without a restart.

### Added

- admin: a server setting now takes effect when it is saved, without restarting the server. Every
  setting carries a class on its console descriptor — applied on save by default, or waiting for the
  next start with a written reason — and the console's standing "waiting for a restart" banner is
  replaced by one that names only the settings genuinely waiting, of which there are none today. The
  settings state reports what is in force on the instance that answered, so a deployment running more
  than one instance is told which values that instance is actually running; the agent-facing surface
  reports the same. A refused submission still changes neither the store nor the running server, and a
  change that would leave a running process holding a configuration it could not have booted with is
  withheld rather than half-applied. Fixes the Sentry card, which claimed "applies immediately" while
  its own endpoint reported the opposite.

- conformance: the server now reports which authentication context a sign-in satisfied. A password
  sign-in, one with a second factor and one delegated to an upstream provider are distinguished, and
  the `acrValues` setting changes from a free-form list to a map from those three to the value each
  is reported as — so an operator can name the vocabulary their relying parties already expect, while
  `acr_values_supported` is derived from those values and cannot advertise a context no sign-in
  produces. Two behaviour changes an integrator could notice: `acr_values_supported` and the `acr`
  entry in `claims_supported` now appear where they were absent, and an unmeetable essential `acr`
  request answers with the registered `unmet_authentication_requirements` instead of looping on the
  login page — with `prompt=none` that replaces `login_required`. On the backchannel path the same
  requirement, unmet, ends the transaction as `transaction_failed` rather than issuing a token whose
  context does not match. A request that asks for no context is unchanged.

- conformance: `pkce.required`, a super-admin setting that relaxes the proof-of-possession demand for
  clients which authenticate at the token endpoint. On by default, so nothing changes for a
  deployment that leaves it alone. It exists because the OpenID Connect Basic profile sends a code
  challenge in one of its 35 modules, so the other 34 were refused before they tested anything, and
  OAuth 2.1 §7.5.1.1 provides for exactly this carve-out — for a confidential client only. A client
  registered with no client authentication is still refused for omitting a challenge whatever the
  setting says, which keeps this server's own public console and agent clients protected by an
  operator's conformance choice.

- conformance: `CONFORMANCE.md` records what the OpenID Foundation suite says about this server —
  twelve plans and 16 680 conditions across two instance profiles, the nine OpenID Provider plans
  among them carrying no failure attributable to this server, and the five defects still open written
  out with the evidence for each. It also records the setup a run needs, because most of the cost of
  a conformance run is not the run. Certification has not been applied for; `SECURITY.md` and the
  assurance page now say that, rather than that the suite has never been run.

- test: coverage for six properties the suite claimed and did not hold — the MongoDB secret round trip
  through the real BSON codec, the PostgreSQL document-column encoding, the timing of both
  constant-time secret comparisons, the discovery document following `ISSUER` rather than a forwarded
  header, and every published agent tool having a route the dispatcher serves. Each was verified by
  reintroducing the defect and confirming the gate fails.

- test: a request to an origin no spec registered used to reach the real network; it is now refused by
  name, with interception installed for every spec so the runner's file order stops deciding it. A
  per-case bound also means a wedged case names itself in twenty seconds instead of idling in silence.

- storage: PostgreSQL is now a supported datastore alongside MongoDB. A deployment picks one by
  which connection string it sets — `POSTGRES_URL` or `MONGODB_URI` — and setting both is refused at
  startup rather than resolved by precedence, since a server that quietly chose the other database
  is indistinguishable from total data loss. `bun run db:setup:pg` provisions the schema and
  `--check` reports on it without writing; documents are stored as `jsonb`, and expired rows are
  reclaimed by a sweeper because PostgreSQL has no TTL index. Nothing above the storage layer
  changed, and existing MongoDB deployments are unaffected.
- storage: a schema-migration layer for both backends, applied by `bun run db:migrate` (`--plan` to
  gate a deploy). Migrations are declared as an ordered set with a checksum, recorded as they run,
  and serialised by a renewable lease so two replicas rolling at once cannot both apply a step. The
  server refuses to start against a database that is behind, ahead, or holding a record for a
  migration whose declaration has since changed. The one-off `managedBy → ownerGroupId` conversion
  has been retired rather than carried into it: a deployment predating ownership groups must upgrade
  through an earlier release first.
- ops: `GET /ready` joins `GET /health`, splitting "don't route to me" from "restart me". Liveness
  answers from the process alone and stays exempt from the rate limiter; readiness reaches the
  datastore, is metered as `public`, holds its last answer for a second so a probe storm cannot
  become database load, shares one outstanding probe rather than starting one per caller, and
  recovers on its own. The probe carries its own five-second deadline, because a driver's timeout
  bounds establishing a connection and not a query on one it already holds: measured against a
  database that was up, connected and no longer answering, an unbounded probe took 30 seconds to
  report anything. Pointing both probes at `/health` turns a database
  outage invisible, since the process is alive and the probe passes while requests keep arriving;
  pointing liveness at `/ready` restarts healthy processes for a database's outage. Both are the
  mistake this split exists to prevent.
- ops: two Fly configurations instead of one. `fly.toml` now describes a deployment that must always
  answer — machines are never stopped for want of traffic, deploys are blue-green so a single-machine
  release costs no downtime, and both probes are wired — while the new `fly.conformance.toml`
  describes a separate app for the OpenID conformance suite that stops when idle and keeps its own
  database. `ISSUER` and `DATABASE_NAME` moved out of secrets into each file's `[env]`, since neither
  is a credential and a config that names its own issuer lets the deploy workflow check the
  advertised one against it. The workflow takes the target as an input, and the release command now
  runs `db:migrate` after `db:setup` so a release carrying its first migration cannot deploy an image
  that refuses to boot.
- security: the release assets now carry provenance of their own. `docs-export.json` and the
  `CHANGELOG.md` a release ships are covered by a single signed SLSA v1 statement, produced the same
  keyless way as the image's and attached to the release as `release-assets.intoto.jsonl`, so a
  download can be verified without reaching back to GitHub for the statement; the release fails if
  the bundle it is about to attach does not verify. The previous argument — that documentation
  nobody executes needs no signature — held for the changelog but not for reference data another
  project's build reads, which is worth a statement naming the commit and the run behind it.

### Changed

- site: a copy-edit of the marketing, comparison and documentation prose for voice (spec 048).
  Sentence rhythm now varies, em-dashes are roughly halved, the repeated "X, not Y" contrast is
  thinned, and judgments (advice, a diagnosis, an assessment of another product) carry a hedge
  where statements of what the server does, a protocol rule or a licence term do not. No
  instruction, command, protocol statement, numeric claim or quoted competitor text changed; the
  build's title, description, FAQ and datastore rules all still pass. `website/DESIGN.md` §Voice
  records the conventions so a new page does not reintroduce the habits.

### Fixed

- protocol: a request parameter the server does not define no longer refuses the request. Ignoring
  one is a `MUST` in RFC 6749 §3.1 **and** §3.2, RFC 8628 §3.1 and CIBA §7.1, and RFC 9126 §2.1
  inherits it for PAR — so `/auth`, `/par`, `/device/auth`, `/backchannel` and `/token` all answer a
  request carrying an extension parameter exactly as they answer one without it, and a Request Object
  may carry extension claims as RFC 9101 §4 permits. The undeclared keys are dropped before
  validation rather than carried, so nothing a client invents is persisted in a pushed request object
  or an interaction record. Because absence from a schema now means "ignore", parameters this server
  must _reject_ are declared explicitly instead: `request_uri` at the pushed endpoint, `request` and
  `request_uri` inside a Request Object, and `authorization_details` at the token endpoint, where
  silently ignoring a client's attempt to narrow its grant would return a broader token than it asked
  for. Elysia's own `normalize` was measured as the alternative and rejected: it also cleans request
  headers, which strips the client certificate and breaks certificate-bound tokens.

- claims: a `claims` request value carrying a top-level member the server does not define is ignored
  rather than refused, at every surface that accepts one. It was declared a closed object, so a value
  naming `id_token`, `userinfo` and anything else was rejected outright where OIDC Core §5.5 says
  other members MAY be present and unrecognised ones MUST be ignored — the defect fixed in `1437341`
  for request parameters, one level deeper, inside a parameter's value. The refusal also named the
  wrong cause: one error string covered every object-level failure, so it reported `userinfo` and
  `id_token` as unsatisfied while both were present. Unknown members are now dropped before anything
  persists the request, so a client cannot make the server keep arbitrary content.

- protocol: a request the schema refuses now answers `400`, not the framework validator's `422`. The
  body was already correct (`invalid_request` with a description); only the status was the
  framework's rather than the protocol's, and RFC 6749 §5.2 defines it as `400`. Scoped to the OAuth
  endpoints: the admin API and `/mcp` keep `422`, where distinguishing a well-formed request with an
  invalid body is what the console and the agent act on.

- pkce: a `code_verifier` containing `.` or `~` is accepted. RFC 7636 §4.1 defines the verifier over
  RFC 3986's `unreserved` set, which includes both; the pattern here was base64url, the alphabet the
  _challenge_ is encoded in and the one this project happens to generate verifiers with. A client
  whose verifier used the full range was refused at schema validation before the grant ran, so its
  code could not be redeemed by any verifier — and since PKCE is mandatory here, that client could
  not use the authorization code grant at all. This is the second correction to the same pattern
  after its length, and both survived for the same reason: nothing this server or its suite produces
  is outside base64url, so it could never trip over itself.

- par: a successful push answered with a JSON body and no `Content-Type`, which goes out as
  `application/octet-stream`, and with status 200 rather than the 201 [RFC
  9126](https://datatracker.ietf.org/doc/html/rfc9126) §2.2 requires — a client that checks the media
  type before parsing, as a FAPI client must, got nothing usable out of the `request_uri`. Only the
  success path was affected; refusals were already correct. The handler now returns the object and
  lets the declared response schema serialize it, which also puts that schema to work for the first
  time: it was bypassed by the hand-built response, and the `status: 201` beside it was never a hook
  Elysia reads.

- par: a pushed `request_uri` is spent by the authorization response it produces even when the user
  had to sign in or consent along the way. One-time use was implemented and correctly placed, but the
  lookup that finds the pushed request after an interaction read `parJti` as a top-level property
  where the value lives on the payload, so it silently found nothing and the record was never marked.
  In practice a `request_uri` survived its own flow and was good for one more authorization — the
  replay RFC 9126 §7.3 describes. The same read appeared in the carry-forward between interactions,
  so a sign-in followed by a consent lost the link entirely. Four reads corrected; no new mechanism.

- userinfo: a request carrying no credentials is answered the way a protected resource must answer
  one — `401` with a `WWW-Authenticate` challenge, and no error information at all. It was being
  treated as an ordinary schema refusal, so the caller got a status RFC 6750 does not use and no
  challenge to act on; the challenge advertises `DPoP` alongside `Bearer` only when DPoP is switched
  on. A credential that is present and unusable is unchanged: that one is refused with `invalid_token`
  and keeps its error body.

- userinfo: the access token may be presented in a form-encoded POST body, which OpenID Connect Core
  §5.3.1 describes alongside the header form. The body form is honoured only under the conditions
  RFC 6750 §2.2 attaches — a POST whose body is form-encoded — and a request that uses both methods
  at once is refused with the `invalid_request` §3.1 specifies; the query-parameter form of §2.3 is
  still not implemented, since OAuth 2.1 removes it and a token in a URL reaches access logs and
  browser history. A DPoP-bound token cannot be presented this way, because RFC 9449 defines no body
  form for it. Two consequences of the same change: a request carrying no credential at all is still
  answered with the bare RFC 6750 §3 challenge, now raised by the handler rather than by the header
  schema, which can no longer require the header; and the route's DPoP proof check asserted
  `htm: "GET"` whatever the method was, so a conforming proof on a `POST /userinfo` was refused as an
  `htm` mismatch — an existing defect nothing had exercised.

- jwks: key generation offers every asymmetric signing algorithm the server knows — `RS256`/`384`/
  `512`, `PS256`/`384`/`512`, `ES256`/`384`/`512`, `EdDSA` and `Ed25519` — in the console and through
  the agent tool, read from the algorithm register rather than restated beside it. It offered only the
  three RSA `RS*` algorithms, which meant a FAPI 2.0 deployment could not be assembled through this
  server's own management surface at all: the profile requires PS256 or ES256, and the operator had to
  write a key straight into the key store. An existing RSA key is still not made to sign PS256 —
  RFC 7517 §4.4 makes a key's `alg` the algorithm it is intended for, and honouring a key past its
  declared intent would let a deployment that pinned a key to one algorithm quietly use another.
  Generating the key you need is the route. The key page also now says when a generated algorithm is
  not yet advertised: discovery's algorithm lists are built at startup, so such a key signs
  immediately but no client asks for it until a restart — previously the page reported no restart
  required, which was true of the key and misleading about the deployment.

- conformance: two findings from the OpenID Foundation suite runs. The `form_post` delivery page
  submits itself with a classic script placed after the form rather than a module script in `<head>`,
  so a user agent that runs scripts but not ES modules — some embedded webviews, and the suite's own
  scripted browser — is no longer left on a page with no way forward at all; the module-capable and
  scripting-disabled paths are unchanged. And a pushed authorization request refused for an
  unregistered `redirect_uri` now answers `invalid_request`, or `invalid_request_object` where the
  value arrived inside a request object, instead of `invalid_redirect_uri` — a dynamic-registration
  code (RFC 7591) that has no definition in a PAR response, where RFC 9126 §2.3 prints the former.
  The authorization endpoint and dynamic registration are untouched. A third item reported alongside
  them — that client assertion audiences are accepted too widely — was investigated and is not a
  defect: RFC 9126 §2 requires a non-FAPI deployment to accept its issuer identifier, token endpoint
  URL and PAR endpoint URL alike, and the narrow FAPI 2.0 rule was already implemented and is now
  covered for all three audience shapes. `CONFORMANCE.md` records the correction and names
  `fapi.enabled` among the settings a FAPI conformance target needs.

## [0.2.0] - 2026-09-08

Two things define this release. The server is now an authorization server **for** third-party MCP
servers rather than only for its own administrative plane, and SECURITY.md has evidence behind it: a
written threat model, a scanning pipeline, and a container image that is signed and ships an SBOM and
build provenance. A plain OAuth 2.1 client can also discover a deployment at last, through RFC 8414
metadata.

### Added

- mcp: the server is now an authorization server **for** MCP servers, not only for its own admin
  plane. An administrator declares a third-party MCP server as a protected resource of a project — its
  canonical identifier, the scopes it recognises, how its tokens are verified, their lifetime — and the
  token endpoint mints audience-bound tokens for it with no source change and no restart; previously
  every audience but `${ISSUER}/mcp` was refused, so protecting one meant writing an addon override.
  A client with no prior relationship gets its project from the declared resource the request names,
  which is what lets it sign in the right deployment's end-users. Client ID Metadata Documents are
  supported as the mechanism the current MCP authorization revision names first: a `client_id` that is
  an https URL resolves by retrieval and validation and creates no client record
  (`clientIdMetadataDocument.enabled`, off by default). The administrative plane admits document
  identifiers through a super-admin allowlist read live, so a withdrawal takes effect on the agent's
  next call; a dynamically registered client can never administer the instance. A new guide,
  [Protect your MCP server with OAuth](https://foxauth.dev/docs/get-started/protect-your-mcp-server/),
  walks it end to end, and the README's compatibility note is replaced by which identity works where.
- security: published evidence behind SECURITY.md, which until now was a policy with nothing standing
  behind it. A written [threat model](https://foxauth.dev/docs/security/threat-model/) names the
  assets, trust boundaries and attackers (RFC 9700 §3) and, for each threat, the control in the code
  and the test that holds it — including the limitations that are true today (secrets unencrypted at
  rest, CSRF resting on `SameSite=Strict`, the image running as root), because a threat model that
  lists only the good news is not one to plan around. A `Security` workflow runs CodeQL (TypeScript
  and the workflows themselves), `bun audit` on both lockfiles failing on high, dependency review on
  pull requests and a Trivy scan of the built image, on every push and weekly; a `Scorecard` workflow
  publishes an OpenSSF Scorecard; a Dependabot configuration keeps the lockfiles and actions current.
  An [assurance page](https://foxauth.dev/docs/security/assurance/) says where each result is read
  and states plainly what does not exist: no external audit, no paid bounty, no OpenID Foundation
  certification. SECURITY.md gained the same section and the README the badges.

- security: the published container image is now **signed, and ships an SBOM and build provenance**.
  `release.yml` signs it with `cosign` over the digest — keyless, so verification names this
  repository, workflow and tag instead of a key we ask you to trust — and BuildKit attaches an SBOM
  and a `mode=max` provenance document to the pushed index that the signature covers; a signed SLSA
  v1 statement also goes to a transparency log for `gh attestation verify` and admission
  controllers. The release verifies its own signature before finishing, so an unverifiable one fails
  the release rather than reaching an operator. The SBOM matters here because the `Dockerfile` runs
  `apk upgrade`, which makes the package set unrecoverable from the repository. Release assets stay
  unsigned on purpose: documentation, not something anyone executes. Verification commands are on
  the [assurance page](https://foxauth.dev/docs/security/assurance/).

- protocol: authorization server metadata at `GET /.well-known/oauth-authorization-server`
  ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), spec 038, issue #30). A plain OAuth 2.1
  client that is not an OpenID Connect relying party looks for this path and no other, so until now
  it could not discover a deployment at all — the endpoint URLs had to be configured by hand, one
  path away from where the server was already publishing them. Served unconditionally, readable from
  any origin and in the public rate class, for the reason the OIDC document is: metadata a client
  cannot read is metadata it cannot use.

  The document is pruned rather than a copy. Both documents come from one builder, so they cannot
  disagree on a shared member, but the OAuth one drops the fourteen members whose subject matter is
  OpenID Connect — the userinfo endpoint and its algorithms, ID token algorithms, subject types, ACR
  values, the claims members, RP-initiated logout and back-channel logout. Membership is decided by
  the registering specification, never by presence in the IANA registry: RFC 8414 invites other
  specifications into that registry and OIDC Discovery accepted, so all 51 members are registered
  there and the obvious check would have admitted the exact document the pruning exists to avoid.
  Twelve members an OpenID specification registered are kept anyway, because an OAuth-registered
  member is unreadable without them — request-object algorithms beside RFC 9101's
  `require_signed_request_object`, the CIBA endpoint beside the CIBA grant in
  `grant_types_supported`, the JARM algorithms beside the `jwt` response modes. Each records that
  anchor as data, and a guard fails naming the member if the anchor is removed or reclassified, so
  the justification cannot outlive what it depends on.

- site: the SEO guardrail now checks that structured data is _present_, not only that it is correct
  (spec 037). It could tell whether a description was well-formed and truthful but not that one
  should exist, which is how the comparison pages shipped with no article markup past twenty passing
  rules. `STRUCTURED_COVERAGE` says what each kind of page must carry, an unclassified route fails
  the build naming the file to edit, and both were shown failing before being trusted.

  Around that: the comparison pages went from one inbound link each to twelve, anchored on the
  competitor's name and derived from the collection so a new one appears everywhere on arrival; the
  pricing and comparison pages publish their questions and answers as structured data from the same
  array the page renders, so the two cannot drift and the existing overclaim rule proves it; the
  documentation index grew from 30 words to a real orientation page and the comparison index gained
  a prose summary; and `llms.txt`, generated in the previous release and pointed at by nothing, is
  now named in `robots.txt` and linked from the footer. Claims about other products are reported as
  due for review after 180 days, in the build log and on the page itself — without failing a build,
  because staleness is the passage of time rather than a mistake to block on. Three comparisons
  were added — Ory Hydra, Zitadel and authentik — each researched against that product's own
  documentation, recording a capability their documentation does not describe as not documented
  rather than as absent.

- site: search and AI discoverability, enforced by the build (spec 036). Every page now carries a
  checked title and summary, a per-page `lastmod` from git, structured data and its own social card —
  documentation pages included, which had none of it because Starlight builds its own head. For
  assistants, `/llms.txt` lists every page where it listed none, `/llms-full.txt` covers the
  marketing and comparison pages it previously omitted, each page is available as Markdown at its
  address plus `.md`, and `robots.txt` names ten AI crawlers with the source and date each was
  checked against. Screenshots are declared in an image sitemap.

  Indexing is now one decision in `website/src/data/seo.ts` — the styleguide used to be excluded by a
  `noindex` in one file and an unrelated string match in another — and twenty rules check the shipped
  HTML, failing the build with the page and the rule. Two defects it caught on its first run are
  fixed: the licence page had two top-level headings, and the settings reference skipped a level.

### Fixed

- security: three latent injection sinks closed, none of them reachable today, which is the only
  reason this is a hardening note and not an advisory. The `WWW-Authenticate` challenge escaped the
  quote in a parameter value and left the backslash alone — the one combination that fails, because a
  value ending in a backslash then escaped the _closing_ quote instead: the quoted string ran on and
  everything after it parsed as further auth-params. Values are now stripped rather than escaped,
  which is what [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) §3 asks for (NQCHAR holds
  neither character), and nothing dynamic reaches a 401 description today only by accident. The
  rendered error page and the device pages interpolated their document title raw, where the plain
  interaction pages already escaped the same position; there is now one escaper in `lib/html/escape.ts`
  with all four callers on it, rather than one file getting it right and its neighbours not.

  The reason the title mattered more than an unreachable sink usually does: the content security
  policy is derived _from_ the finished document, so an injected inline script would have been hashed
  and then authorized by the very header meant to stop it. That chain is now pinned by a test that was
  watched failing — it emitted a `sha256-` for `alert(1)` — rather than left as an argument.

  Separately, every tag and attribute matcher in the policy derivation now reads a document by the
  grammar a browser uses rather than a stricter one. Three spellings of that mistake were found, and
  each of the last two only after the previous was fixed: a tag name is case-insensitive, so `<SCRIPT>`
  was a different tag to the deriver than to the parser; and an end tag may carry both whitespace and
  attributes, so `</script >` and `</script foo="bar">` ended a script everywhere except here. All
  three failed the same way — the block went unrecognized, its hash was never issued, the browser
  blocked a script the page still believed it served, and the page rendered perfectly with the
  capability silently gone. None is a hole; all are the kind of wrong that reports itself nowhere.

  The end-tag pattern is now taken from the corpus the analyser itself checks a regex against rather
  than reasoned about one spelling at a time, which is what produced two of the three rounds. It
  deliberately does not accept `</scriptfoo>` — a tag named `scriptfoo` — since reading that as a close
  would hash the wrong span rather than none.

- test: the invariants behind the escaping and the policy derivation are now checked against generated
  input rather than examples (`test/properties/invariants.spec.ts`, `fast-check` as a dev dependency).
  Both had just cost three rounds each of the same shape: a fix was written for the one spelling that
  had been reported, the suite went green, and the next spelling arrived on the next scan. An example
  answers "does it handle this?"; these state what is true of every input — a challenge carries no
  character that could end a parameter early, every inline script a document serves is authorized by
  the policy derived from it whatever the tags are spelled, `</scriptfoo>` is never read as a close, the
  escaper leaves nothing that could escape its position, and a base32 secret survives being retyped in
  a different case with spaces in it.

  Each property was checked by reintroducing the bug it exists to catch, which is the only way to know
  a property has teeth — and the first draft did not. It passed against the restored escaping bug,
  because a full-Unicode generator has no reason to favour one ASCII character and that invariant is
  about exactly two of them; five hundred runs produced no `"` at all. Generating from the characters
  that actually break the function fails it on the fifth case and shrinks the counterexample to a
  single quotation mark. The lesson is in the file, next to the generator.

- build: the container image no longer ships known-vulnerable OpenSSL, and the base it inherits is now
  a reference rather than a moving target. One package accounted for twenty of the twenty-five open
  scanner alerts — `libssl3`/`libcrypto3` 3.5.7-r0, two high, six medium, twelve low — and the standing
  plan of waiting for the base image to be rebuilt turned out not to work: measured on a fresh pull,
  `oven/bun:alpine` still carried 3.5.7-r0 while Alpine's v3.22 repository already served the fixed
  3.5.8-r0, so cutting a release would have rebuilt from the same vulnerable layer.

  `FROM` is now pinned by digest, and to a versioned tag rather than the floating `alpine`, because
  that is the only form anything keeps current: Dependabot moves a digest when the tag's version
  changes and has no mechanism for "same tag, newer digest"
  ([dependabot-core#1971](https://github.com/dependabot/dependabot-core/issues/1971)), so
  `alpine@sha256:...` would have frozen the image at the day it was written — which is exactly why it
  had been left unpinned. A `docker` entry in the Dependabot configuration keeps the pin moving, and
  `apk upgrade --no-cache` takes the distribution's patches at build time rather than inheriting the
  unpatched half of the digest. Reproducibility over time is the deliberate cost; within a run the
  scan and the release still build identically, and `bun.lock` still pins the application's own
  dependencies. Verified with the Security workflow's own Trivy flags: zero fixable findings at every
  severity, down from twenty.

- ci: the release workflow no longer grants every job write access. `contents: write` and
  `packages: write` sat at the top level, so the test job — which runs whatever a version tag points
  at — held a token that could push to the repository and publish to the registry, for no reason
  beyond the two jobs beside it needing one each. Read at the top, write only where a write happens,
  the shape the security workflow already used. CodeQL also stops scanning `test/`: thirteen of twenty
  high-severity alerts were test assertions — a `redirect_uri` written as a regex with an unescaped
  dot, a `<script>` string a CSP test looks for, a password hashed by a fixture — ranked beside two
  real findings in `lib/` that nobody could see for the noise. An alert list is a queue, and a queue
  that is two-thirds false is not read.

- ci: a commit that touches only the console's React components no longer fails the coverage gate.
  Those components are pulled into the coverage run by the shell's module graph but never rendered by
  it, so they report between 1% and 10%, and their 5,923 lines drag the project number from 97% to
  82% — which Codecov then holds every other commit to. One duly failed at 63% of a diff that was a
  single `.tsx` file. A `codecov.yml` ignores the browser bundle and changes no target, because every
  commit scored on server code has hit 100% of its diff; the two modules beside those components that
  `bun test` does exercise stay measured. They are verified where they run, by the Playwright capture
  in the site build.

- test: the login throttle specs no longer sit one second away from bun's 5s default timeout. Each
  spends the failure cap and each attempt costs an argon2 verification, so the file runs at roughly 3s
  per test and contention from the rest of the suite decides the rest — which it did once, and a
  timeout is reported as a failing assertion, reading like a broken throttle rather than a slow one.
  The budget is stated once at the top of the file.

- site: the home page no longer scrolls sideways on a phone. Below the `lg` breakpoint the hero grid
  declared no base column count, so it formed a single implicit `auto` track sized to its content —
  the page laid out 839px wide inside a 375px viewport, with the headline running off-screen. A grid
  track's automatic minimum is `min-content`, so one unbreakable string sets the width of the whole
  page; `overflow-x-auto` on the element does not save it, because by then the ancestor track has
  already grown. Every grid now carries an explicit `grid-cols-1`, the settings reference uses
  `minmax(0,1fr)` rather than `1fr` for the same reason, and long identifiers in prose break instead
  of widening the page. Three pages were affected, the settings reference and the changelog beside
  the home page; all thirteen now measure no overflow at fourteen widths from 320px up, with the
  desktop layout unchanged.

### Security

- ci: every GitHub Action is pinned to a full commit SHA with the version beside it in a comment,
  where all twenty were previously mutable tags and one — the Fly deployment's `setup-flyctl` — was
  the `master` branch. A tag is a pointer its owner can move, so the workflows granted whatever
  those repositories held at the moment a job started, including the ones holding the registry
  credential and the release token. This is the OpenSSF Scorecard `Pinned-Dependencies` check, which
  scored 0 against the badge the README publishes, and the gap was invisible in review precisely
  because a version tag reads like a version. Dependabot updates a pinned SHA and its comment
  together, so the pins stay current rather than merely frozen.

  Landed with the five action upgrades this made necessary to resolve — `checkout` to v7.0.1,
  `upload-artifact` to v7.0.1, `upload-pages-artifact` to v5.0.0, `metadata-action` to v6.2.0 and
  `action-gh-release` to v3.0.3. `upload-pages-artifact` stops including dotfiles as of v4, which the
  site build does not emit; `deploy-pages` stays on v4, which that version still requires.

## [0.1.0] - 2026-09-03

The first tagged release: everything the server accumulated before a version number existed.

### Added

- Reported faults now name where in the server they happened (spec 035). An operator paged about a
  failure could see which endpoint broke but not which line broke it, and had to open the internal
  console and look the reference up to find out — while every fault on one endpoint arrived under a
  byte-identical title, so a list of alerts could not be scanned at all. A reported fault now carries
  the code location the internal record already held, is titled with the diagnostic message rather
  than a synthetic endpoint string, and is located by a second line built from the method, the route
  pattern and that code location. The file is also a searchable tag, so an operator can ask what is
  failing in one part of the server rather than only inspecting one fault at a time. Grouping is
  untouched: the store's own key is still the only thing the destination groups on, and it already
  incorporated the code location. Nothing else was widened — the location joined the explicit list of
  permitted outbound fields, which is now enforced one level deeper so a value added inside it later
  cannot ship unnoticed, and a raw stack, an error object, or a frame still carrying the failure
  message remain unsendable.
- Optional Sentry reporting for recorded faults (spec 034). The error store already kept a durable
  record of every unexpected internal fault, but nothing told anyone one had happened — an operator
  learned about a failure by going to look for it. With `sentry.enabled` on and an ingestion
  credential configured, each fault the store records is also reported to the operator's own Sentry
  project, carrying the endpoint, the kind of failure, the client it is attributable to and the same
  `error_reference` the caller received, so an alert leads straight back to the full internal record.
  The environment and release labels are read from what the deployment already declares — `NODE_ENV`
  and the `package.json` version — rather than typed into the console, because a label maintained by
  hand is stale from the next deploy onwards, and a stale release label sends an investigation to a
  build that never ran. No new environment variable was introduced for it; the console shows the
  resolved values read-only instead.

  Off by default, one instance-wide destination, super-admin only, and it requires the error store:
  the outbound event is projected _from_ the internal record, so reporting is an additional
  destination and never an alternative to recording. The ingestion credential is write-only through
  the admin surface — a read reports only whether one is stored, and the audit trail records that it
  changed without recording its value.

  The **official `@sentry/elysia` plugin is deliberately not used**, and that is the substance of the
  work. Reading its source (v10.73.0) showed three disqualifying behaviours: its capture predicate
  reads the response status and reports when it is still `undefined`, so routine `invalid_grant` /
  `invalid_client` rejections — the normal traffic of a token endpoint — would ship as unhandled
  faults; it attaches the full request URL and headers unconditionally, which on `/authorize` means
  `state`, `code_challenge`, `id_token_hint`, `login_hint`, `request_uri` and on an error redirect
  `code`, plus `Authorization` and `DPoP`; and it writes `sentry-trace`/`baggage` onto every response
  while opening spans across all nine Elysia lifecycle phases. Instead `@sentry/bun` is used directly
  with `defaultIntegrations: false` and no integrations, as an envelope-and-transport layer only.
  `lib/sentry/` registers no Elysia hook at all, so there is no code on the request path to add a
  header, add latency, or fail; the event is assembled from a named list of permitted fields
  (excluding `actor` and `userAgent`) rather than by scrubbing a captured request, and dispatch
  happens from exactly one place — inside `captureFault`'s record continuation, which runs only after
  the fault is classified and locally recorded. Outbound volume is bounded by `sentry.queueDepth`
  with counted drops, so an error storm cannot amplify into the monitoring channel. The default test
  run performs no outbound delivery yet can inspect exactly what would have been sent, which is what
  makes the data-protection guarantees assertions rather than review opinions.
  `wiki/concepts/sentry-plugin-not-used.md` records the reasoning; `test/sentry/` holds it.

- Brute-force protection on the password sign-in door (issue #9, spec 032). `POST /ui/:uid/login`
  accepted unlimited guesses against any address, each one buying a full password hash on a
  shared-CPU machine — so the door was both a credential-stuffing opportunity and a cheap
  CPU-exhaustion vector, and the only unbounded secret surface left in the server. Failed attempts
  are now counted per `${bucketId}:${email}` in a new `LoginThrottle` area; at the cap the door shuts
  for that address and refuses everything — **including the correct password** — until the window
  ends, and each further exhaustion shuts it for longer, doubling 15 → 30 → 60 minutes. That holds a
  sustained attack to roughly 120 guesses a day against unlimited before, and a refused attempt does
  no lookup and no hashing, so the CPU half of the issue closes with the guessing half.
  The refusal is the door's existing invalid-credentials page, produced by the _same expression_ the
  two ordinary failure paths use rather than a copy of the wording, and failures are counted for
  addresses that resolve to no account — so neither the response nor the existence of a counter is
  evidence that an address is registered. Two things clear a counter, and both are proofs an attacker
  guessing passwords does not hold: a password that verifies, and a **completed** password reset.
  The second is why no "enter the code from your email" step was built — consuming the emailed secret
  already proves control of the address, through a flow that has its own cooldown and cap, while a
  dedicated step would have been an account-existence oracle, an email-bombing vector, a hard mail
  dependency for sign-in, and unavailable to the one bucket with no reset at all. Requesting a reset
  clears nothing.
  Three decisions are worth reading the code for. The record's retention (24h from the last failure)
  must **outlive** its own lockout window or the escalation silently never happens — a counter reaped
  when the door reopens restores the opening allowance, so an attacker who waits is never escalated;
  the boot validator enforces the ordering. The escalation ceiling is the first window wherever the
  bucket sets `totpRequired`, read from the bucket's policy and never from its identity, because a
  guessed password is not a sign-in there while the lockout it risks — the admin console, which has no
  self-service reset — is the one nobody can undo. And the counter's key is built by one new
  `emailScopedId` helper stating its rule as parity with `findByEmail`'s normalization: a key built
  from the raw submission would have given a 16-letter address 65,536 independent counters, and every
  test written in lower case would still have passed. That helper replaced three copies of the
  expression and one inlined fourth in the end-user delete route which had dropped its `toLowerCase()`
  — under the in-memory adapter, whose user store does not normalise what it stores, that line was
  already missing the email-scoped records of mixed-case accounts and reporting success.
  Bounds are `loginThrottle.failureCap`, `.windowSeconds` and `.windowCeilingSeconds`, super-admin
  editable and boot-only. There is deliberately no `loginThrottle.enabled`: unlike the per-origin
  limiter this is persisted, holds across restarts and machines, and is therefore a security boundary
  rather than a resource protection — a kill switch for it is a switch that reopens the vulnerability,
  so the validator bounds the numbers to a range in which the protection still means something instead.

- The last three security headers issue #2 asked for (issues #10 and #2, spec 029).
  `Strict-Transport-Security: max-age=63072000; includeSubDomains` and a `Permissions-Policy` denying
  seventeen high-privilege browser features now ride on every response, from the same pre-routing hook
  that already carried `nosniff`, `Referrer-Policy` and the non-page content policy — so they reach the
  error pipeline, the named admin instance and static assets, which after-the-fact response hooks miss
  silently. `preload` is deliberately omitted and the reason recorded: the deployment host is already
  preloaded through the whole `dev` TLD, submission needs an apex domain this deployment does not own,
  and the effect is global and slow to undo — a self-hoster's choice to add at their own edge. HSTS is
  emitted unconditionally, including over plaintext, because TLS terminates at the proxy so the hop RFC
  6797 governs is HTTPS, and the alternatives are either spoofable (`X-Forwarded-Proto`) or invisible
  to the merge gate. `clipboard-write` is **not** denied, and a named test enforces that: antd's
  `copyable` reaches for `navigator.clipboard.writeText` first, so denying it would have stranded five
  secret-copy surfaces — the TOTP enrolment secret among them — on the deprecated `execCommand` path.
  The legacy `X-Frame-Options: DENY` is emitted by `htmlResponse` on rendered pages only, derived from
  the same single evaluation as `frame-ancestors` and therefore absent on the one deliberately framable
  page, the `form_post` hand-off; a blanket emission was not merely inelegant but unimplementable,
  since a returned `Response` can override a merged header but never remove one and the header has no
  permissive value, so it would have broken silent authentication with no downstream fix
- Per-origin request rate limiting (issue #1). An origin that spends its allowance inside a window is
  refused with `429` and a `Retry-After`, before the endpoint does any work. Allowances are tiered by
  route class rather than blanket — strict on the unauthenticated and expensive surface, loose on
  static assets and discovery, the liveness probe exempt — declared as a third dimension on the route
  table under the same two-way drift guard as the feature gate and CORS. Counting is per instance and
  never persisted, so no storage area is added; the price is that the effective allowance multiplies
  by concurrent machine count and clears on restart, which is why this is a resource protection and
  not a security boundary. The per-identity throttles are unchanged, and the login door's brute-force
  protection remains issue #9. Nine `rateLimit.*` settings, editable from the console; invalid values
  refuse the boot rather than serving with limiting silently absent. `elysia-rate-limit` was evaluated
  and not adopted: its single static `errorResponse` cannot produce this server's three channel
  shapes, and its default refunds requests whose handler threw — which is every failed credential
  guess
- The administration console can be put behind the second factor. A new settings resource under
  `/admin/api/admins` carries the reserved admin bucket's `totpRequired` — audited as
  `admin.settings.update`, exposed to MCP as `admin_settings_read` and `admin_settings_update`, with
  a switch on the Admins page. The generic bucket routes still refuse that bucket; this is the
  surface their 403 already pointed at. Nobody is locked out by turning it on: an administrator
  without an authenticator enrols at their next sign-in
- TOTP second factor per user bucket: `totpRequired` makes a password sign-in also require a
  six-digit authenticator code, with enrolment at registration and at the first sign-in of an
  existing account, RFC 4226/6238 implemented in-repo against the published test vectors, replay and
  two-tier throttling, `amr: ['pwd','otp']` on the ID token, and operator recovery via
  `DELETE /admin/api/buckets/:id/users/:uid/totp` (audited, ends sessions, exposed to MCP as
  `bucket_user_totp_clear`). Federated sign-in is not gated (spec 027)
- CORS support: preflight handling, open CORS on discovery/JWKS, client-based CORS on the token
  family driven by a per-project `corsOrigins` allow-list, `cors.enabled` setting (spec 011)
- Hardening headers on every response that is not a rendered page — `nosniff`, `no-referrer`, and a
  content policy of `default-src 'none'` plus `frame-ancestors 'none'` — across the protocol
  endpoints, the admin API, MCP and the static surface, including responses built by the error
  pipeline. Rendered pages keep their own derived policy (spec 026)
- Content-Security-Policy on every rendered page, derived per document — `script-src 'none'` on
  script-free pages, hashed inline styles; hydrated pages use precompiled antd CSS under
  `zeroRuntime` (specs 018/032, `74cc208`, `1a4628d`)
- Admin audit trail covers all 23 mutating admin routes and became readable:
  `GET /admin/api/audit` + an Audit page in the console (spec 016)
- Rich Authorization Requests (RFC 9396) work end to end on the code and refresh flows: consent
  display, grant persistence, working hook defaults, per-client `authorizationDetailsTypes` via
  the admin API (spec 015)
- Self-service end-user password reset, bucket-scoped, with throttling (spec 020)
- Upstream OIDC federation per bucket — end users sign in through their own identity provider;
  admin management plane included (spec 022)
- Admin MCP control plane: administer the instance from an AI agent at `POST /mcp`, served as an
  OAuth 2.1 protected resource of the server itself (spec 024)
- Durable server error store an operator can read — internal faults no longer vanish with the
  console (spec 025)
- `bun run db:setup` provisions every collection and index from a declared storage inventory under
  a drift guard, including TTLs for verification areas and unique per-bucket email indexes
  (spec 012)

### Changed

- Groups read as themselves in the admin console, and a personal group is nobody else's to work in.
  Four things were wrong at once, all of them about the same list. Every personal group displayed as
  the bare word "Personal" — including in a super administrator's list, where N administrators
  produced N identical rows and the owner's email that is _stored_ as the group's name was thrown
  away by both display sites. Personal groups appeared in the Groups table at all, which is a page
  about the teams work is shared with. `GET /admin/api/scope` offered a super administrator every
  group on the instance, other people's personal groups among them, and `PUT` accepted them — so the
  console could be pointed at one person's own workspace by somebody who was never in it. And the
  reserved holding group was called "Unassigned", which reads like a data-quality problem rather than
  the name of the one group that is not a tenant.
  It is now: **System** (`SYSTEM_GROUP_NAME`, `$set` by the deployment seed so an existing database is
  renamed too, and preferred over the stored name by the console so it does not wait on `db:setup`);
  no personal rows in the Groups table; and one `groupLabel` helper shared by the table and the scope
  switcher, rendering "Personal" for your own and "Personal — owner@email" for a personal group you
  were added to. Both scope routes now apply the same carve-out — the list never offers what the
  switch would refuse — and all three of the switch's refusals still say one thing, so it cannot be
  used to learn which ids are real or which of them are personal. Whether a personal group is your
  own is answered by the server from `members[0]`, the only place that can answer it: a shared
  personal group may promote a second owner, and `findPersonalFor` matches any personal group you are
  a member of
- Switching the console's active scope no longer writes to the audit trail. `PUT /admin/api/scope`
  changes `AdminSession.activeGroupId` and nothing else, and grants no access a member did not already
  have — while which scope a change was made from is already carried by `ownerGroupId` on that change's
  own entry. It joins `POST /admin/api/logout` in `excludedAdminRoutes`, whose reason already described
  it: session lifecycle, not a change to a managed entity. `scope_switch` is withdrawn from the agent
  surface with it, as `inapplicable` — an agent has no console session, so the tool could only ever
  answer 400
- `README.md` and `AGENTS.md` now describe the server that exists (issue #20, spec 031). The endpoint
  table was wrong on six of eleven rows — `/authorize`, `/introspect`, `/revoke`, `/register`,
  `/session/end` and `/request` are really `/auth`, `/token/introspect`, `/token/revocation`, `/reg`,
  `/logout` and `/par` — and was missing twelve routes and every method on `/userinfo` but `GET`. It is
  now derived from `lib/consts/route_classification.ts`, which pairs each route with its governing flag
  and is already guarded both ways against `elysia.routes`, and it is split by availability because 23
  of the 28 feature flags default off and a disabled endpoint is deliberately indistinguishable from
  one that does not exist. Five Features bullets had presented opt-in capabilities as shipping
  defaults, Client Credentials and Refresh Token among them; the Features list now separates what a
  default install serves from what a deployment switches on, and drops the claim of static client
  registration, which was removed when clients became DB-backed. The Standards table gained eleven
  implemented specifications plus a flag column, and admits CIBA, JARM and OAuth 2.1, which its
  RFC-only shape had excluded. `AGENTS.md` had pointed contributors and agents at `/interaction/*`
  routes; login and consent are served under `/ui/:uid/*`. Two claims the issue asked for were dropped
  after checking the code: RFC 8414 is not implemented, and no `/.well-known/oauth-authorization-server`
  is served
- **BREAKING:** feature flags now gate their endpoints — a disabled feature's routes answer 404
  instead of staying silently live (spec 010)
- **BREAKING:** deletion means what it reads as — projects/buckets refuse deletion while non-empty
  (409 with machine-readable blockers); deleting a client or end-user cascades to their sessions,
  grants and tokens (spec 019)
- **BREAKING:** pairwise `sub` values derive from stored server state instead of `os.hostname()`.
  They change exactly once, on first start of this version, for clients registered
  `subjectType: 'pairwise'` — then never again across restarts and scale-out (spec 023)
- **BREAKING:** `richAuthorizationRequests.types` is now a serializable descriptor map (`label`,
  per-common-field constraints, `allowUnknownFields`) editable in the admin settings; enabling the
  feature with an empty map fails validation. A code-registered `validate` remains an optional
  escape hatch (spec 015)
- **BREAKING:** `allowOmittingSingleRegisteredRedirectUri` moved into the Application
  Configuration (`authorization.allowOmittingSingleRegisteredRedirectUri`) and now defaults to
  **disabled**; enable it in the admin settings and restart to restore the old behavior
- Interaction UI: post-registration "check your inbox" notice renders, registration refusals are
  styled pages, consent permissions carry headings and friendly labels, decorative Google button
  removed (spec 021)

### Removed

- Seven unreferenced modules deleted (issue #19, spec 030): the whole `lib/views/` directory of legacy
  interaction templates — safe because spec 015's `'rar-detail'` consent group had taken over the RAR
  rendering that was its one unique job — plus the `Stub.tsx` admin placeholder, `helpers/params.ts`,
  `helpers/set_www_authenticate.ts` and `helpers/_/pick_by.ts`. The two addon functions the issue
  suspected of being dead are **kept**: `assertClaimsParameter` and
  `assertJwtClientAuthClaimsAndHeader` are live override seams reached through the call-time registry
  in `lib/addon/index.ts`, so an empty body is their default rather than an abandoned stub, and each
  now carries a comment saying so. `AGENTS.md`'s source-tree map lost three stale entries it had kept
  describing — `views/`, the long-deleted `provider.ts`, and CORS under `shared/`. Test counts, type-error
  count and lint findings all held at their pre-change values.

### Fixed

- A super administrator's scope switch is no longer accepted and then silently discarded.
  `resolveActiveGroup` (`lib/admin/auth/rbac.ts`) re-validated the session's choice against membership
  alone, with no exception for the role that is allowed to switch without one — so a super
  administrator switching into a group answered 200, and on the very next request their active scope
  resolved to empty and `assertActiveGroup` sent everything they created to the `unassigned` holding
  group while the console went on showing the group they picked. Their choice is now honoured after
  one re-read of the group, which also refuses it if the group has since been deleted or is an
  administrator's personal group

- An agent naming an operation the MCP surface withholds now hears why, instead of `Tool <name> not
found`. The refusal text existed and never ran: the call that delivered it sat in the tool
  registration loop, where it can only fire for a name that _is_ registered, and an excluded operation
  never is. It now also runs in the transport, before the SDK and after the credential, answering a
  failed tool call rather than a JSON-RPC error. A genuine typo still gets the SDK's not-found, so a
  mistake is not dressed up as a policy decision
- The server could not boot against MongoDB: the DPoP nonce secret came back from the driver as a
  BSON `Binary` and failed its own round-trip check (`71d9b53`)
- PKCE accepts the full RFC 7636 verifier length range (43–128), not only 43 (`6dce3f7`)
- Native clients can complete an interactive sign-in (`ba5629d`)
- Interaction pages can hand off to a foreign callback under the CSP (`271d518`)
- The settings audit records only the fields a save actually changed (`b630c73`)
- Logging out of the admin console actually signs the operator out: it now ends the provider
  session as well as the console's own, and clears both cookies with the `Path` they were set with
  (Elysia's `cookie.remove()` omits `Path`, so the browser defaulted it to the request's directory
  and cleared a different cookie)
- The interaction cookie is cleared at its own path and expires with the interaction: the clear went
  out with `Path=/` while the cookie lives at `/ui/<uid>` (a different cookie, so a browser kept it),
  and its `Max-Age` was set in milliseconds -- a ~41-day lifetime for a one-hour interaction
- Small-batch fixes: duplicate first-run admin setup surface removed, error pages carry the real
  status and illustration, stale `interaction.returnTo` corrected, unimplemented CIBA `push` mode
  removed from the admin schema (spec 018)

### Security

- The reserved admin bucket can no longer be gated on email verification. Both paths that create an
  administrator write `verified: false` and no verification mail is ever sent for that bucket, so the
  flag would have refused every administrator at the door with no way back short of editing the
  database. It was unreachable through the API rather than prevented; it is now refused at the point
  of enforcement
- The end-user cookies (`_session`, `_interaction`) carry `Secure` -- and the `/ui/*` responses,
  which is where the authenticated `_session` is first written, now carry the full
  `HttpOnly; SameSite=Strict; Secure` set instead of no attributes at all: that route family
  declared a second, option-less cookie schema, so a `Set-Cookie` from it inherited nothing.
  Both schemas now build from one `endUserCookieAttributes` owner
- The admin console verifies its id_token's signature (plus `nonce`, expiry, audience) against the
  live keystore before trusting it — previously a documented decode-only shortcut (spec 017)
- The DPoP nonce secret is self-provisioned at startup, making the requireNonce-without-secret 500
  state unrepresentable (spec 014)

[Unreleased]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/RedFox-Soft/OAuth-server.ts/releases/tag/v0.1.0
