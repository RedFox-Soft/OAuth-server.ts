---
type: concept
title: 'The bucket is the only container'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-15
updated: 2026-10-15
graph:
  node_type: concept
---

# The bucket is the only container

Since spec 099 an administrator group owns **buckets**, and nothing else. A bucket holds its end users, its
sign-in configuration, its **applications** (OAuth clients) and its **APIs** (declared protected resources).
Each application and each API names the bucket it belongs to, on its own record, for its whole life. The
**project** — a container that sat between a group, a bucket and a list of clients — is gone: no type, no
store, no `/admin/api/projects*` routes, no `project.*` audit actions, no `project_*` tools.

## Why the project went

The project was a folder carrying a second copy of ownership. It had to name a bucket of its own group
(spec 098), it held its clients as a list, and in practice there was one per bucket. That second copy was
the source of real defects:

- **A client could fall out of its project.** Membership was `Project.clientIds`, written
  read-modify-write by the client routes, so two concurrent creates could lose one. A client that dropped out
  belonged to no project, fell to resolver rule 5 and signed people into the shared Default bucket — where its
  tenant-set `consent.require: false` was then honoured, because "in no project" meant "the operator's own".
  That was a cross-tenant consent bypass.
- **Lookups were nondeterministic.** "The project of this client" was a `LIMIT 1` over a list with no
  uniqueness, so a client listed twice got arbitrary CORS origins and machine-token answers.
- **The administrators' MCP client could be broken.** A super administrator could re-point the console's own
  project and break agent sign-in.
- **Client changes were invisible to tenants.** Their audit entries carried no group, so a tenant's trail
  did not show them.
- **One answer leaked existence.** Naming another group's project answered differently from naming one that
  did not exist.

The rejected alternative kept the project as a child of its bucket. It still put membership on the parent,
so the first two defects stayed. Dropping the project's unique slug would also have broken MongoDB, whose
`slug_1` unique, non-sparse index collides on `null`. Renaming "bucket" to "project" in the same change was
split off as a separate change: the word would otherwise have changed meaning in the middle of a migration
that removes `projectId`.

## The industry pattern

Almost every identity provider keeps applications flat inside the user pool: an Auth0 tenant, a Keycloak
realm, a Cognito user pool, a FusionAuth tenant. A layer under the pool earns its place only where it carries
roles, grants or delegation — Zitadel's projects do — and ours carried none. Branding was never on it either:
a client's logo and links are already per client ([[consent-screen-decisions]]).

## What replaced each thing the project did

| The project did | Now |
|---|---|
| Listed its clients (`clientIds`) | The client stores `bucketId`, a server-only base key (`lib/models/client/wire.ts:76`, `lib/configs/clientSchema.ts:171`). Listed through `ModelAdapter.findByIndexed('bucketId', …)` (`lib/adapters/types.ts:316`) over the Client area's `payload.bucketId` index (`lib/consts/storage_inventory.ts:343`) |
| Pinned its clients to its bucket (resolver rule 2) | Rule 2 reads the stored client's `bucketId` (`lib/admin/auth/resolveBucket.ts:62-65`, `:86-90`); the Default bucket still does not pin (`:151-154`) |
| Carried the bucket a self-registered client came from (`registeredAtBucket`) | Folded into the same `bucketId`, written by DCR at an addressable bucket (`lib/actions/registration.ts:229`) and carried forward on update (`:369`) |
| Held one allowlist of browser origins | Each client stores `corsOrigins` (`clientSchema.ts:180`), read by CORS from the stored record (`lib/plugins/cors.ts:198-199`), matched by exact equality |
| Owned declared resources (`projectId`) | A resource stores `bucketId`; the store lists, destroys and re-namespaces by bucket (`listByBucket`, `destroyByBucket`, `moveBucketNamespace`, `lib/adapters/types.ts:1330`) |
| Decided who may mint machine tokens for its resources | A stored client of the resource's bucket that did not register itself (`machineTokenPermitted`, `lib/resources/registry.ts:100-115`) — see [[mcp-server-authorization]] |
| Decided the consent waiver ("the project's group owns the bucket") | `clientBelongsToBucket` (`lib/models/client/provenance.ts:40-47`): the client's `bucketId` is the bucket signed into |
| Gave its group reach over its bucket | Nothing. A group reaches a bucket only by owning it (`holdsBucket`, `lib/admin/auth/can.ts:65-70`) |
| Moved alone, or with its bucket | Only a bucket moves; what it holds follows by reference, with no write of its own ([[container-ownership-transfer]]) |
| Blocked its own deletion while holding clients | A bucket refuses deletion while it holds operator-registered applications or APIs (`lib/admin/buckets/routes.ts:654-677`) |
| The console's admin project held `admin-mcp` | Both administrators' clients carry `bucketId: ADMIN_BUCKET_ID` in the seed (`lib/consts/admin_seed.ts:100`, `:121`) |

The administrative routes for both live under the bucket: `/admin/api/buckets/:id/clients[/:clientId[/secret]]`
(`lib/admin/clients/routes.ts:81-178`) and `/admin/api/buckets/:id/resources[/:resourceId[/vouching]]`
(`lib/admin/resources/routes.ts:205` onward). Reading needs the bucket's `read` right, changing its `edit`
right, and `edit` is false on the administrators' bucket for everyone (`can.ts:195-199`). An application or
API named under a bucket that does not hold it answers exactly as a missing one (`clients/routes.ts:44-53`,
`resources/routes.ts:179`). Audit entries for both carry the bucket as `bucketId` and its group as
`ownerGroupId` (`clients/routes.ts:69-71`), which closes the tenant-visibility gap.

## Gotchas

**Only the server writes `bucketId` or `corsOrigins`.** Both are base keys, not registration metadata, so
the wire translation drops them: neither a registration request nor a client metadata document can name the
bucket it signs people into or grant itself CORS. Every update path carries them forward because no admin
body ever emits `bucketId`. There is no operation that changes an application's bucket, on any surface.

**CORS must read the stored record, never `Client.find`.** `Client.find` resolves a client metadata
document, so reading origins through it would let an `Origin` header trigger an outbound fetch to a URL the
caller chose. `adapter('Client').find` has no such branch.

**A self-registered application is listed but not managed.** A bucket's client list includes clients that
registered themselves at its address, but PATCH, secret rotation and DELETE refuse them with 409
(`assertManaged`, `clients/routes.ts:60-67`): they are managed through their registration access token, and
their consent setting must stay what the registration made it. They never block a bucket's deletion
(`bucketClients(…, true)`, `buckets/routes.ts:244-259`), and they never get machine tokens.

**`findByIndexed` takes only a declared single-field index.** Every adapter calls `assertIndexedField`
(`lib/consts/storage_inventory.ts:953-964`) before it queries, so a listing is never a scan and no
caller-chosen name reaches a query. `findByOwner` was not reused, because the cascade engine reads the owner
fields and a bucket is not that kind of owner.

**A tenant can no longer have an application on the Default bucket.** Its group is the System group, so
only a super administrator holds it. The upgrade turned `consent.require` back on for applications that came
from tenant groups' projects on the Default bucket: keeping a tenant's "skip consent" there would waive
consent across the shared population.

## The upgrade

Migration `2026-10-16-remove-projects` (`lib/consts/migrations.ts:1276`, not reversible) reads the old
area by its literal name, `LEGACY_PROJECTS_AREA` (`:115`). The area is gone from `STORE_AREAS`, and its
collection or table stays on disk, because provisioning never drops anything. In order, it:

1. refuses, writing nothing, when one client is listed by projects on different buckets, naming them;
2. writes each listed client's `bucketId` and `corsOrigins` from its project, only where absent — from the
   earliest-created project when one bucket has several, reported; ghost ids are reported, not written;
3. folds `registeredAtBucket` into `bucketId` and unsets it;
4. gives `admin-panel` and `admin-mcp` the administrators' bucket (seeds only insert);
5. turns consent back on for the Default-bucket applications of tenant groups, reported;
6. moves each resource's `projectId` to `bucketId` — a resource without a project gets its namespace when that
   is a bucket id, and the Default bucket otherwise, reported;
7. reports buckets where several projects declared resources, because machine tokens there now widen to every
   operator-registered application of the bucket.

Every write is conditional on the target being absent, so a second run writes nothing. The real-database
check is `database/verify_remove_projects.ts`.

## Related

- [[group-ownership]] — the ownership model, now with one kind of container.
- [[container-ownership-transfer]] — moving a bucket, which carries its applications and APIs by reference.
- [[mcp-server-authorization]] — declared APIs, the resolver rules and machine tokens, keyed by bucket.
- [[consent-screen-decisions]] — the waiver and the provenance tiers, decided by `clientBelongsToBucket`.
- [[client-registration-attributes]] — why `bucketId` and `corsOrigins` are base keys.
- [[bucket-is-an-issuer]] — the bucket as issuer, which is what makes it the natural container.

Verified against [[oauth-server-codebase]].
