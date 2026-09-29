---
type: concept
title: 'The issuer is the unit of tenant isolation'
tags: [architecture, contract, security]
sources: [oauth-server-codebase]
created: 2026-09-29
updated: 2026-09-29
---

# The issuer is the unit of tenant isolation

Two things used to be instance-wide and are now per issuer:

- the namespace a declared protected resource is unique in;
- the key set that signs a tenant's tokens.

Both changes answer one audit finding, which had two halves.

- **Squatting.** Any group member could declare another tenant's MCP server URL, first come, first
  served. The real owner got a permanent 409, and rule 3 routed that server's clients into the
  claimant's bucket.
- **One key set for everyone.** A token one tenant minted verified at another tenant's resource server.
  Separation rested entirely on that resource server checking `iss`.

## Why the issuer, and not the bucket or the project

This follows the model of Keycloak realms, Okta authorization servers and Auth0 tenants: an issuer is
the boundary a relying party already reasons about. Its metadata, its `iss` and its `jwks_uri` all
belong to it. The counter-model is Entra ID, whose tenants share signing keys and are told apart by
`iss`/`tid`. Getting that check wrong is a known class of multi-tenant vulnerability, and this server's
own resource servers are third-party code nobody here reviews.

A bucket with an address, whether a path or a hostname, is an issuer ([[bucket-is-an-issuer]]).
Everything served at the root shares one issuer: the default bucket, the administrators bucket and a
bucket with no address. So all of those share one namespace (`@root`) and one key set (the instance
keys). Giving them separate key sets would mean one issuer publishing keys that some of its own tokens
do not verify against. Both the namespace and the key set are keyed by bucket **id**, not by issuer
string, so a move between path and hostname changes the issuer and keeps both.

## Why the root namespace is super-admin only, and nowhere else needs proof

Inside a bucket with its own address, a declaration can only claim that bucket's namespace, so nothing
about the resource is fetched. That is what makes internal-network, loopback and not-yet-deployed MCP
servers declarable. At the root, tenants genuinely share one namespace. A resource's RFC 9728 metadata
can say it trusts the root issuer but not *which* root tenant it belongs to, so no proof closes
squatting there. The interim fix (7322716) was such a proof, and it also refused every legitimate
private server. What does close squatting at the root is a rule about who may write, so the root
namespace is super-admin only (`assertMayWrite`, `lib/admin/resources/routes.ts`). A tenant that wants
to declare for itself gets a bucket with an address. [[mcp-server-authorization]] has the mechanics:
the composite key, rule 3's required address argument, moves between namespaces, and the diagnostic the
proof became.

## The switch to per-bucket keys had no transition, on purpose

When a bucket first needs a key, it gets one immediately (`ensureBucketKey`). There is no period in
which it still signs with the root keys, and the root keys never appear in its set. That departs from
Constitution VI ("key rotation must not invalidate currently valid tokens") for exactly one moment: a
token a bucket signed with the root keys before the upgrade stops verifying at that bucket's resource
servers. It was the owner's decision, taken while no deployment had users. Keeping the root keys in
each bucket's set for a token lifetime would have held the cross-tenant gap open for that window. If a
deployment ever gains users before an equivalent change, that fallback is the one to restore. Ordinary
rotation after the switch complies in full ([[signing-keys]]).

## A TTL, because there is no messaging

Every instance caches a bucket's key set for 30 s (`KEY_CACHE_SECONDS`, `lib/keys/issuer_keys.ts`). This
server has no cross-instance messaging for anything, settings included, so a TTL is the only bound on
how far another instance can lag. The rotation rules are written against it:

- a key must stay published for twice the TTL before it may sign;
- a retired key stays published for a day, the longest a signed artefact lives.

With those two rules, the lag never lets one instance sign with a key another does not yet serve.

## Found on the way

- Four signers passed no bucket to `IdToken`, so their `iss` was the root at every named bucket: signed
  userinfo, JWT introspection, JARM and the logout token. That was fixed first, in 22f276a.
- The setup scripts baselined every declared migration on every run, and the release command runs setup
  before `db:migrate`. The first real migration would therefore have been marked applied and never run.
  They now baseline only a database they built from empty (9a06d07).
