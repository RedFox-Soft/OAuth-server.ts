---
type: concept
title: 'Authorization for MCP servers'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-09-08
updated: 2026-09-08
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
project fell through to a hard-coded `redfox` bucket, which is what the README's compatibility note
recorded.

## A declared resource is data, and read every time

`lib/resources/` owns two things: the canonical form of an identifier and the lookup that turns one
into a `ResourceServer` descriptor. The addon default gained a middle arm — built-in MCP audience,
then the store, then the existing `mustChange` stub — so an override still wins for everything else and
the failure mode for an unknown audience is unchanged.

**There is deliberately no cache in front of the store.** A deleted declaration has to stop issuance on
the *next* request, which a memo would defer; `test/resources/issuance.spec.ts` pins it. Same reasoning
as `tryFindClient` reading the adapter every call, after a TTL-less client memo once served a stale
client to the admin plane.

The descriptor and the `jwt` access-token format already existed
(`base_token.ts` reads `resourceServer.accessTokenFormat`), so **no issuance code changed at all**. That was the largest
simplification in the feature and it was not visible from the spec.

## The identifier is the primary key

`protectedResources._id` **is** the canonical resource identifier, so instance-wide uniqueness is what
the datastore enforces rather than a rule a route remembers. The route reads before inserting for a
better message and treats the insert failure as the same conflict, because the read is a race and the
key is not.

Canonicalization is one function used by *both* sides — declaration and request — which is what makes
them unable to disagree. `resourceIdentifierMatches` takes the same options as
`canonicalizeResourceIdentifier`, and that parameter is not decoration: without it the declaration's
trailing slash is stripped too, so a resource that declared the slash significant would collapse into
its sibling and a request for the slash-free one would take its token. The first version of this had
that bug; the test did not catch it, reasoning did.

## Which bucket a request signs into: five rules, and every caller must pass the resource

`resolveBucketForRequest(clientId, resource?)` resolves, in order: reserved console client → admin
bucket; client in a project → that project's bucket; **one** declared resource named → that resource's
project's bucket; a permitted client identity naming the administrative MCP audience → admin bucket;
otherwise `redfox`.

Rule 3 is the answer to what `specs/024-admin-mcp-control-plane/research.md` D6 left open, and it is
safe for the reason D6's rejected version was not: **an administrator authored the resource**, in a
project they own, whose bucket is their own choice. An attacker cannot declare a resource, so the
parameter selects among an operator's options and cannot create one. `${ISSUER}/mcp` is not a declared
resource — the built-in arm claims it and declaration refuses it — so the admin bucket is unreachable
through rule 3.

**The gotcha.** Every caller must pass the resource it has, `findAccount` included. It did not, at
first: login resolved the project bucket and found the user, `findAccount` resolved `redfox` and did
not, so `loadGrant` left `oidc.grant` unset and the consent prompt crashed with a 500 rather than
refusing. A caller that omits the resource silently resolves a different bucket than login did.

## A client whose id is a URL, stored nowhere

The current MCP authorization revision (2026-07-28) marks dynamic client registration **deprecated**
and names OAuth Client ID Metadata Documents first. `lib/client_metadata_document/` implements that in
four modules, and the split is deliberate: `fetch.ts` is the whole egress boundary and knows nothing
about JSON shapes, so it can be reviewed for one question only — can a caller make this server talk to
something it should not.

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

Enforced in **two** places, and both are needed. The bucket rule lets the administrator sign in;
`lib/mcp/principal.ts` re-checks on every call, which is what makes a withdrawal land on the agent's
next request rather than when its token expires. That is the remedy an operator needs when a permitted
host is taken over.

The loopback interlock is the sharp edge. A document offering only loopback redirect targets proves
control of a domain but cannot prove *which local process* will receive the code — the specification
says so and calls the warning a SHOULD. Here the stake is administrative authority, so it is an
interlock: the route refuses until the administrator acknowledges, and the words the route refuses with
are the same exported string the console renders as the acknowledgement. The console tells the two
kinds of 409 apart by a flag, never by matching the message text.

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
(§4.2, §6.1) for loopback impersonation, and it was the first recommendation made during clarification.
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

- [[admin-mcp-control-plane]] — the plane this feature makes reachable by a second kind of client
- [[group-ownership]] — what a project's owning group decides, which a declared resource inherits
- [[client-identity-from-database]] — the adapter-every-call rule the resource registry follows, and the memo whose staleness is why the registry has none
