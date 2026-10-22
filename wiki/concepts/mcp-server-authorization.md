---
type: concept
title: 'Authorization for MCP servers'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-09-08
updated: 2026-10-22
graph:
  node_type: concept
---

# Authorization for MCP servers

The server was already an MCP-capable authorization server for exactly one MCP server: its own
administrative plane. Every protocol piece existed — protected resource metadata, resource indicators,
dynamic registration, PKCE, DPoP — and all of it pointed at itself. Two things stood in the way of an
operator using it for their own MCP server, and both were fixed by turning code into data.

`getResourceServerInfo` threw `InvalidTarget` for every audience except `${ISSUER}/mcp`, so protecting
a third-party resource meant writing an addon override in this repository. And a client belonging to no
old-style Project (a retired project; since spec 099: to no project) fell through to the hard-coded `redfox`
project — the Default project — which is what the README's compatibility note recorded.

A project is stored as a bucket (`UserBucket`); the code keeps that name, and the console and the admin API
have said "project" since spec 100. Since spec 099 a declared resource — an **API** in the console — belongs
to a project, stored as `bucketId` on the declaration, as an application does
([[project-is-the-only-container]]). Until then it belonged to the old Project entity, removed in spec 099
(a retired project), by `projectId`.

## A declared resource is data, and read every time

`lib/resources/` owns two things: the canonical form of an identifier and the lookup that turns one
into a `ResourceServer` descriptor. The addon default gained a middle arm — built-in MCP audience,
then the store, then the existing `mustChange` stub — so an override still wins for everything else and
the failure mode for an unknown audience is unchanged. (Since 2026-10-06 a SCIM arm comes first: the
addressed project's `<issuer>/scim/v2`, held only by that project's provisioning connections, whose clients are
refused every other indicator, MCP's included — see [[scim-provisioning]].)

**There is deliberately no cache in front of the store.** A deleted declaration has to stop issuance on
the *next* request, which a memo would defer; `test/resources/issuance.spec.ts` pins it. Same reasoning
as `tryFindClient` reading the adapter every call, after a TTL-less client memo once served a stale
client to the admin plane.

The descriptor and the `jwt` access-token format already existed
(`base_token.ts` reads `resourceServer.accessTokenFormat`), so **no issuance code changed at all**. That was the largest
simplification in the feature and it was not visible from the spec.

**What the end user is told comes from the declaration too** (since spec 092). A declared resource may
carry `scopeDescriptions`: per scope, a `description` in the administrator's words and an optional `kind`,
`see` or `act` (`lib/adapters/types.ts:1290-1290`, `:1309`). Absent, the kind is `act`. The consent page
heads each resource with its declared name and its host, and lists a described scope under "see" or "act"
(`lib/interactions/consentView.ts:462-442`). An undescribed scope is shown only by its technical name,
under "not described". A description may only name one of the resource's scopes; changing `scopes` without
sending descriptions prunes the removed scopes' entries (`lib/admin/resources/routes.ts:150`, `:327-336`).
Nothing is taken from the resource's own metadata or an MCP server's tool list. See
[[consent-screen-decisions]].

## Unique within a namespace, and the namespace is the issuer

A declaration is unique within its **namespace**: the project id of an addressable project, or `@root` for
everything served at the root issuer — the Default project, the administrators' project, a legacy project
with no address (`namespaceOf`, `lib/resources/namespace.ts:18-24`). The namespace is still derived from the
project's address, and `bucketId` is stored beside it, because `@root` cannot say which project a declaration
belongs to. The stored
`_id` is the two joined by one space (`lib/resources/declaration_id.ts`), which a canonical identifier
cannot contain, so the datastore's primary key is still what enforces uniqueness rather than a rule a
route remembers. The route reads before inserting for a better message and answers only the store's
`UniqueValueTaken` as the same conflict, because the read is a race and the key is not. Until
2026-09-29 the identifier alone was the key — instance-wide and first come, first served (changed in
3e377b8).

Keyed by project id, not issuer string, because a move from path to hostname changes the issuer and not
the tenant. Every resolution reads only the namespace of the address the request arrived at
(`getResourceServerInfo` from `oidc.bucket`, `lib/addon/resources.ts`), so two tenants with issuers of
their own may declare the same URL, and a request at one never reaches — or learns of — the other's:
it gets the `invalid_target` an undeclared identifier gets. `test/resources/namespace_resolution.spec.ts`
is the case.

**Reading a project's APIs.** `GET /admin/api/projects/:id/resources` (`lib/admin/resources/routes.ts:210-228`,
MCP `resource_list`) answers `{ namespace: 'project' | 'root', resources }` (the value was `'bucket'` until
spec 100): the project's own declarations, read with `listByBucket`. For a project served at the root it lists
only that project's declarations, because the rest of `@root` belongs to other tenants. Since spec 099 this is
the collection route the declare, read, update, delete and vouching routes sit under, and the console shows it
as the project's APIs tab. Spec 085's version of the route listed the namespace's declarations with the old
Project (a retired project) that made each, published as `bucket_resource_list`; both went with the old
Project entity in spec 099.

Canonicalization is one function used by *both* sides — declaration and request — which is what makes
them unable to disagree. `resourceIdentifierMatches` takes the same options as
`canonicalizeResourceIdentifier`, and that parameter is not decoration: without it the declaration's
trailing slash is stripped too, so a resource that declared the slash significant would collapse into
its sibling and a request for the slash-free one would take its token. The first version of this had
that bug; the test did not catch it, reasoning did.

## Which project a request signs into: five rules, and every caller must pass the resource

`resolveBucketForRequest(clientId, resource, addressed)` (`lib/admin/auth/resolveBucket.ts:46-75`) resolves,
in order: reserved console client → the administrators' project; a client that belongs to a project → that
project, read from the stored record's `bucketId`; **one** declared resource named → that resource's
`bucketId`; a permitted client identity naming the administrative MCP audience → the administrators' project;
otherwise `redfox`, the Default project. Since spec 099 rule 2 is one rule: it used to read the client's old
Project (a retired project), and a separate rule 2b read `registeredAtBucket` for a client that registered
itself at a project's address. Both are now the client's `bucketId`, which only the server writes
([[client-registration-attributes]]). `admin-mcp` reaches the administrators' project through its own
`bucketId`, not through the console's former, now retired, project.

Belonging to `redfox` does **not** end resolution at rule 2 or 3 (`pinnedBucketOf`, `resolveBucket.ts:151-154`):
until spec 098 an old Project (a retired project) on it named no bucket — no project in today's sense — and
its clients went on through rules 3 and 4, and neither the migration that wrote `redfox` into such old
Projects nor spec 099's was meant to move a single sign-in. `test/admin/resolve_bucket.spec.ts` holds that an
application on the Default project resolves exactly as a client in no project does.

Rule 3 answers a question the admin MCP control plane left open, and it is
safe for the reason the rejected version was not: **an administrator authored the resource**, in a
project they hold. An attacker cannot declare a resource, so the
parameter selects among an operator's options and cannot create one. `${ISSUER}/mcp` is not a declared
resource — the built-in arm claims it and declaration refuses it — so the administrators' project is
unreachable through rule 3.

"An attacker cannot declare a resource" held only for attackers without a console account (corrected
2026-09-29). Any member of any team could declare, identifiers were unique across the instance, and
first won — so a hostile tenant could declare somebody else's MCP server, leave the real owner a
permanent 409, and route that server's clients into the tenant's own project. The first fix (7322716)
made every non-super-admin declaration prove itself through the resource's RFC 9728 metadata, which also
refused every internal-network, loopback and not-yet-deployed server. It was replaced the same day by
namespaces: a declaration in a project with its own address makes no outbound request at all — it can
only be a claim on that project's own namespace — and rule 3 takes the addressed project as a required
argument and chooses only among projects sharing that issuer (`lib/admin/auth/resolveBucket.ts`). At a
named address it can therefore only confirm the address. `test/resources/declaration.spec.ts` covers the
declarations that now need nothing.

**What is left of the proof is a diagnostic.** `checkVouching` (`lib/resources/vouching.ts`) answers,
for any declaration and blocking nothing, whether the resource's metadata currently describes it and
lists the issuer its tokens carry — the project's own, or `ISSUER` at the root, never `issuerFor` of a
project with no address, which would be `<ISSUER>/<id>`. It follows the MCP discovery order the old proof
skipped the first step of: a `Bearer` challenge's `resource_metadata` on an unauthenticated **GET** (a
diagnostic must not POST to somebody else's server), then path-inserted, then root well-known, all
through the egress boundary. It returns only enums and the expected issuer — no fetched text — so an
agent reading it through `resource_vouching_check` reads nothing a third party wrote. The console
fetches it per row after the list renders. `test/resources/vouching.spec.ts`.

**The root namespace is a super administrator's.** Every tenant served at the root shares its issuer,
and a resource's metadata can say it trusts that issuer but not which of those tenants it belongs to —
so no proof closes squatting there. Create, amend and remove at `@root` answer 403 for anyone else,
naming the way out: give the project an address of its own (`assertMayWrite`,
`lib/admin/resources/routes.ts:109-113`, wording in `lib/admin/resources/refusals.ts:6-7`). `test/resources/root_namespace.spec.ts` is the attack, through the
console and through an agent.

**Declarations move with their project's address.** A declaration's namespace is derived from its project's
address, so a project that gains its first address without them would leave declarations that no longer
resolve anywhere. `planMove`/`applyMove` (`lib/admin/resources/move.ts`, called from the address change at
`lib/admin/buckets/routes.ts:1079-1095`) carry them, through the store's `moveBucketNamespace` in one call; a
target that already declares one of the identifiers answers 409 with the list, and a move into `@root` is held
to the rule above. The plan is checked before the audit write; the store undoes its own moves on a race the
plan could not see. Until spec 099 they also moved, one at a time, when an old Project (a retired project)
was reassigned to another bucket — what is now a project; that operation is gone. `test/host_buckets/address_change.spec.ts`.

**The gotcha.** Every caller must pass the resource it has, `findAccount` included. It did not, at
first: login resolved the client's project (then reached through its old, now retired, Project) and found
the user, `findAccount` resolved `redfox` and did not, so `loadGrant` left the grant unset and the consent
prompt crashed with a 500 rather than refusing. A caller that omits the resource silently resolves a
different project than login did.

It happened again, and that time it was a hole rather than a crash (corrected 2026-09-29). The password
door, the reset door, the registration door and the enrolment step's second-factor check resolved the
project from the client alone, so for a client in no old Project (now: of no project) they read the
*Default* project's policy while the sign-in used the resource's. A federated-only project reached through a
declared resource verified
passwords against its accounts, mailed resets that set a password on a federated account — around the
provider's factors and offboarding — and let registration create password accounts. `passwordDoorClosed`
now takes the interaction and `loginOptionsForClient` a required `resource`, so the omission no longer
type-checks; `test/cimd/resource_bucket_doors.spec.ts` is the attack.

## A machine token goes only to the project's own applications

Rule 3 is safe for a sign-in because an end user consents: any client, one belonging to no project
included, may *ask* a person for a token to a declared resource. A client credentials token asks
nobody. Until 2026-09-28 `getResourceServerInfo` ignored the client, and the grant took its project from
the request address, so any confidential client of any tenant — or one that registered itself —
could call `/b/<victim-slug>/token` and receive a token with the victim resource as its audience, the
victim project as its issuer and the victim's scopes: everything a resource server checks. Only
`client_id` differed.

`machineTokenPermitted` (`lib/resources/registry.ts:100-115`) now refuses it with `invalid_target` unless
the client is **stored**, its `bucketId` is the resource's `bucketId`, and it did not register itself; and
`client_credentials.ts:87-98` asks before minting. A client metadata document has no stored record and is
refused; a self-registered client of the same project is refused because nobody vouched for it. Until spec 099
the test was "the client is in the old Project (a retired project) that declared the resource", so a bucket —
today's project — shared by several such Projects kept their machine audiences apart; the upgrade reports such
projects, because every operator-registered application of the project now qualifies. A list of grantees on
the resource was rejected, because it would reproduce the read-modify-write membership list that let a client
fall out of its old Project. An identifier
nobody declared is not its question — the built-in MCP audience and an addon override answer for themselves.
`test/resources/machine_access.spec.ts` is the attack. Since spec 110 (2026-10-22) the grant also refuses, as an unknown client, any
client that does not belong to the project whose address it was requested at, resource or no resource: a client
of no project otherwise got a resource-less token bearing that project's issuer ([[project-is-an-issuer]]).

**A machine token also needs a client that authenticates** (2026-10-20). Until then a stored, same-project,
operator-created client registered with `token_endpoint_auth_method: none` passed every check above: the token
endpoint accepts `none` with no proof (`lib/shared/token_auth.ts`), so anyone who read the client_id off an
authorization URL — it is public, and the console's form defaulted to `none` — received machine tokens for every
API the project declared. A test asserted it as "accepted". RFC 6749 §4.4.2 and OAuth 2.1 confine the grant to
confidential clients. `client_credentials.ts` now answers `unauthorized_client` to a `none` client, which binds
every client already stored; the admin route (`lib/admin/clients/service.ts`) and the console refuse the
combination with 422, as does CIBA's backchannel endpoint for its grant. The list is
`lib/consts/confidential_grants.ts`; since spec 108 it also holds the token-exchange, JWT bearer and `jwt-dpop`
grants, whose handlers refuse a `none` client the same way ([[enterprise-managed-authorization]]). It is deliberately **not** in the registration validator yet: every lookup
re-validates, so a rule there would stop such clients resolving for their browser sign-ins too.

## A client whose id is a URL, stored nowhere

The current MCP authorization revision (2026-07-28) marks dynamic client registration **deprecated**
and names OAuth Client ID Metadata Documents first. `lib/client_metadata_document/` implements that in
four modules, and the split is deliberate: `fetch.ts` knows nothing about JSON shapes, so it can be
reviewed for one question only — can a caller make this server talk to something it should not. It
stops at 5 KB (`MAX_DOCUMENT_BYTES`, `lib/client_metadata_document/fetch.ts`) and makes **one** request:
a 200 or nothing, no redirect followed (`maxRedirects: 0`, which `guardedFetch` answers by returning the
redirect unread). The address classes it will reach and the time bound are `lib/shared/egress.ts`'s. The
whole branch is gated on `clientIdMetadataDocument.enabled`, **off by default**
(`lib/configs/application.ts:699`), because it lets an unauthenticated caller make this server issue an
outbound request.

**Written to draft -02 since spec 110** (2026-10-22); it was built to -00, which MCP 2026-07-28 still cites.
-01 and -02 only narrow what a server accepts, so following them serves a client written to either:

- **One request, 200 only** (-02 §5: "MUST NOT automatically follow HTTP redirects", every other status
  "an error response"). Until spec 110 up to four https redirects were followed and any 2xx accepted.
- **A published secret refuses the document** (§4.1). It used to be dropped, on the reasoning that the harm
  was only in honouring it; -02 lists the secret properties beside private key material, which the client
  model already refused, and a document that publishes one was written by someone expecting confidential
  authentication they will not get.
- **No `token_endpoint_auth_method` means `none`.** The RFC 7591 default, `client_secret_basic`, demanded a
  secret no document can hold, so such a document — an ordinary public client — failed as
  `invalid_client_metadata` at `/auth`.
- **Every refusal is `invalid_client`.** `tryFindClient` turns an `InvalidClientMetadata` from the client
  model into "no client", the answer every other document failure already got.
- **Addresses inside the document are https** (§8.6: the special-use-address rule covers "any URLs contained
  within" it): `registerClient` runs the write-time TLS check of specs/103 for documents too, which have no
  record, so every value is new.
- **Identifiers are compared as written** (§3). The administrative allowlist stored `URL.href`, which
  lowercases the host and drops a default port, so an entry for `https://Tools.Example.com/client` could never
  match — and the route then could not even add it, since it checked the document against the parsed form.

**It was not the only such request** (corrected 2026-09-28). `fetch.ts` used to say it was "the only
place this server makes an outbound request on behalf of an unauthenticated caller", and three more
went through plain `fetch`: the sector document (`sector_identifier_uri`), the client's key set
(`jwks_uri`) and the back-channel notifications (CIBA ping, back-channel logout) — every one an address
the registrant chose, and for a document-identified client the sector check ran on every `/auth`.
Redirects were followed wherever they led, nothing refused `169.254.169.254` or `10/8`, nothing bounded
time or size, and the sector refusal repeated the status the target answered, which made it a port
scanner. The egress rules moved out of `fetch.ts` into `lib/shared/egress.ts` — `guardedFetch`
(`:157`) and `readBounded` (`:211`), a streaming byte bound rather than a read-then-measure — and all
four go through them. The sector refusal is now one message whatever went wrong. The range check compares addresses as numbers (a `node:net` `BlockList`) and judges the IPv4 an IPv6 address carries — mapped, compatible, SIIT, NAT64, 6to4 — because URL parsing rewrites `[::ffff:169.254.169.254]` as `[::ffff:a9fe:a9fe]`, which the first, text-matching version let through (corrected 2026-09-29).
`test/egress/client_addresses.spec.ts` is the attack, and `test/preload.ts` resolves every name to one
public address so no spec depends on the machine's DNS.

Federation's requests joined it on 2026-09-29 — discovery, the code exchange, GitHub's token exchange
and the upstream key set (`lib/federation/discovery.ts`, `flow.ts`, `identity/profile_api.ts`, `jwks.ts`,
the last through jose's `customFetch`). They had been left out as "an administrator's addresses, not a
stranger's", which undersold both halves: any team member can set an issuer, the discovery document it
serves names the token endpoint and key set, and an unauthenticated visitor sets the requests off again by
starting a sign-in. Discovery now also refuses an endpoint that is not https.

Three traps live here.

**The branch order in `tryFindClient` is load-bearing.** It sits *after* the adapter read. URL-shaped
client ids are not new — `test/client_id_uri/` covers DCR issuing one through a deployment's
`idFactory` — so a branch placed first would shadow every such stored client with a retrieval that
must fail. Adapter-first is also safer: a stored record always wins, and a DCR id is server-generated
so it cannot claim a legitimate document identifier.

**Dot segments cannot be checked on a parsed URL.** Bun's parser resolves them away before anyone can
look, percent-encoded ones included: `/a/%2e%2e/c.json` parses to `/c.json`. The rule is applied to the
raw input. Verified, not assumed.

**Nothing is remembered on a failure.** The draft forbids caching an error response or an invalid
document, and the reason is practical: a transient outage or one attacker-supplied malformed document
would otherwise sit in front of a working one for the life of the entry. Expressed as control flow —
the store is never handed a failure — rather than as a rule someone has to honour.

## The administrative plane admits documents, never registrations

A dynamically registered client can never administer the instance, under any configuration: its
identity is minted on demand by whoever asked, so there is nothing an operator could meaningfully
allowlist. A document identifier can, once a super administrator names it — a stable URL is
allowlistable, which is precisely the operator decision D6 found missing.

Enforced in **two** places, and both are needed. The project-resolution rule lets the administrator sign in;
`lib/mcp/principal.ts` re-checks on every call, which is what makes a withdrawal land on the agent's
next request rather than when its token expires. That is the remedy an operator needs when a permitted
host is taken over.

The loopback interlock is the sharp edge. A document offering only loopback redirect targets proves
control of a domain but cannot prove *which local process* will receive the code — the specification
says so and calls the warning a SHOULD. Here the stake is administrative authority, so it is an
interlock: the route refuses until the administrator acknowledges, and the words the route refuses with
are the same exported string the console renders as the acknowledgement. The console tells the two
kinds of 409 apart by a flag, never by matching the message text.

Since spec 092 the consent page states the stake as well. When the request's `resource` is the
administrative MCP, the page shows one red block: the app will be able to do anything you can do in the
console. It is recognised by the requested resource, not by scope (`lib/interactions/index.ts:798-802`),
because the plane's only scope is `openid` and a repeat consent would otherwise show nothing. The page
shows one warning at most, and this one outranks the rest, the loopback warning included
([[consent-screen-decisions]]).

The whole permission list is **withheld** from the agent surface, reads included. An agent granting
another agent administrative access is a privilege escalation, and a list of permitted identities is a
list worth impersonating.

## Two mechanisms rejected, and why they looked cheaper

Reclaiming unused registrations wanted an expiry index on the `Client` area. The storage inventory
refuses that at the `Client` entry: `MongoAdapter.upsert` never `$unset`s a stale `expiresAt`, so the
first administrator-created client that ever acquired one would be deleted silently — "inert now,
unrecoverable later". A partial index covering only self-registered rows is not something `IndexSpec`
can express. What is left is an explicit sweep behind a new adapter method (`destroyUnusedSince`),
which is how Principle III says a new storage requirement should be expressed, run opportunistically at
registration time — the only moment that both correlates with growth and is already paying for a write.

Restricting a permitted identifier's redirect targets to its own origin is what the CIMD draft names
(-00 §4.2, §6.1; -02 §8.1) for loopback impersonation, and it was the first recommendation made during clarification.
§4.2 then expects an authorization server that restricts them to operate a public metadata-document
service for developers in compensation — which this project will not do — and the restriction would
exclude every local agent host, which is most of them. Rejected, and the risk carried explicitly
instead.

## Where the specification does *not* decide

Two things worth knowing, because both look like conformance questions and are not.

**Token format.** The specification mandates neither: an MCP server must reject tokens not intended for
it "or otherwise verify that they are the intended recipient", which admits both a self-contained token
and introspection. The default here is self-contained because the alternative obliges a reader to
switch introspection on and provision credentials first, and the ten-minute guide has no room for it.

**Scope accumulation.** Assigned to the *client*, explicitly, so "servers remain stateless with respect
to client scope sets". Scope-hierarchy sufficiency belongs to the resource server. All that falls to
this server is naming the required scopes in a challenge — which `/mcp` now does.

## See also

- [[per-issuer-isolation]] — why declarations are unique per issuer and the root namespace is super-admin only
- [[admin-mcp-control-plane]] — the plane this feature makes reachable by a second kind of client
- [[team-ownership]] — what a project's owning team decides, which a declared resource inherits
- [[project-is-the-only-container]] — why a declaration stores `bucketId`, and the upgrade that moved the retired project's `projectId` to it
- [[client-identity-from-database]] — the adapter-every-call rule the resource registry follows, and the memo whose staleness is why the registry has none
