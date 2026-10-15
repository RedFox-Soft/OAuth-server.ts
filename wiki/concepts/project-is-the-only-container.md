---
type: concept
title: 'The project is the only container'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-15
updated: 2026-10-15
graph:
  node_type: concept
---

# The project is the only container

**Two things on this page share a name, so read this first.** A **project** here is today's container. The
code stores it as a bucket (`UserBucket`, area `userBuckets`; what it holds names it as `bucketId`), and
spec 100 renamed it at the edge. In the same rename the administrator group that owns a project became a
**team** (stored as `Group`). The thing spec 099 removed is a different, older entity that was also called a
project. This page calls it the **retired project** every time. Its stored audit entries (`project.*`, target
type `Project`) present as `retiredproject.*` and `RetiredProject`, so the two never merge. "Project"
without "retired" always means today's.

Since spec 099 a team owns **projects**, and nothing else. A project holds its end users, its sign-in
configuration, its **applications** (OAuth clients) and its **APIs** (declared protected resources). Each
application and each API names the project it belongs to, on its own record (`bucketId`), for its whole
life. The **retired project** — a container that sat between a team, a project and a list of clients — is
gone: no type, no store, no routes, no audit actions, no tools. (Its routes were `/admin/api/projects*` and
its tools `project_create`, `project_bucket_assign` and the like; since spec 100 those path and tool
prefixes name today's project, which is a different thing.)

## Why the retired project went

The retired project was a folder carrying a second copy of ownership. It had to name a project of its own
team (spec 098), it held its clients as a list, and in practice there was one per project. That second copy
was the source of real defects:

- **A client could fall out of its retired project.** Membership was `Project.clientIds`, written
  read-modify-write by the client routes, so two concurrent creates could lose one. A client that dropped out
  belonged to no retired project, fell to resolver rule 5 and signed people into the shared Default project —
  where its tenant-set `consent.require: false` was then honoured, because "in no project" meant "the
  operator's own". That was a cross-tenant consent bypass.
- **Lookups were nondeterministic.** "The retired project of this client" was a `LIMIT 1` over a list with
  no uniqueness, so a client listed twice got arbitrary CORS origins and machine-token answers.
- **The administrators' MCP client could be broken.** A super administrator could re-point the console's own
  retired project and break agent sign-in.
- **Client changes were invisible to tenants.** Their audit entries carried no owning team, so a tenant's
  trail did not show them.
- **One answer leaked existence.** Naming another team's retired project answered differently from naming
  one that did not exist.

The rejected alternative kept the retired project as a child of its project. It still put membership on the
parent, so the first two defects stayed. Dropping the retired project's unique slug would also have broken
MongoDB, whose `slug_1` unique, non-sparse index collides on `null`. Renaming "bucket" to "project" in the
same change was split off as a separate change (spec 100, since done): the word would otherwise have changed
meaning in the middle of a migration that removes `projectId`.

## The industry pattern

Almost every identity provider keeps applications flat inside the user pool: an Auth0 tenant, a Keycloak
realm, a Cognito user pool, a FusionAuth tenant. A layer under the pool earns its place only where it carries
roles, grants or delegation — Zitadel's projects do — and the retired project carried none. Branding was
never on it either: a client's logo and links are already per client ([[consent-screen-decisions]]).

## What replaced each thing the retired project did

| The retired project did | Now |
|---|---|
| Listed its clients (`clientIds`) | The client stores its project as `bucketId`, a server-only base key (`lib/models/client/wire.ts:76`, `lib/configs/clientSchema.ts:171`). Listed through `ModelAdapter.findByIndexed('bucketId', …)` (`lib/adapters/types.ts:316`) over the Client area's `payload.bucketId` index (`lib/consts/storage_inventory.ts:343`) |
| Pinned its clients to its project (resolver rule 2) | Rule 2 reads the stored client's `bucketId` (`lib/admin/auth/resolveBucket.ts:62-65`, `:86-90`); the Default project still does not pin (`:151-154`) |
| Carried the project a self-registered client came from (`registeredAtBucket`) | Folded into the same `bucketId`, written by DCR at an addressable project (`lib/actions/registration.ts:229`) and carried forward on update (`:369`) |
| Held one allowlist of browser origins | Each client stores `corsOrigins` (`clientSchema.ts:180`), read by CORS from the stored record (`lib/plugins/cors.ts:198-199`), matched by exact equality |
| Owned declared resources (`projectId`) | A resource stores its project as `bucketId`; the store lists, destroys and re-namespaces by project (`listByBucket`, `destroyByBucket`, `moveBucketNamespace`, `lib/adapters/types.ts:1330`) |
| Decided who may mint machine tokens for its resources | A stored client of the resource's project that did not register itself (`machineTokenPermitted`, `lib/resources/registry.ts:100-115`) — see [[mcp-server-authorization]] |
| Decided the consent waiver (the retired project's team owns the project signed into) | `clientBelongsToBucket` (`lib/models/client/provenance.ts:40-47`): the client's `bucketId` is the project signed into |
| Gave its team reach over its project | Nothing. A team reaches a project only by owning it (`holdsBucket`, `lib/admin/auth/can.ts:65-70`) |
| Moved alone, or with its project | Only a project moves; what it holds follows by reference, with no write of its own ([[container-ownership-transfer]]) |
| Blocked its own deletion while holding clients | A project refuses deletion while it holds operator-registered applications or APIs, with "project still holds applications or APIs" (`lib/admin/buckets/routes.ts:654-681`) |
| The console's admin retired project held `admin-mcp` | Both administrators' clients carry `bucketId: ADMIN_BUCKET_ID` in the seed (`lib/consts/admin_seed.ts:100`, `:121`) |

The administrative routes for both live under the project: `/admin/api/projects/:id/clients[/:clientId[/secret]]`
(`lib/admin/clients/routes.ts:83-184`) and `/admin/api/projects/:id/resources[/:resourceId[/vouching]]`
(`lib/admin/resources/routes.ts:215` onward) — `/admin/api/buckets/…` until spec 100. Reading needs the
project's `read` right, changing its `edit` right, and `edit` is false on the administrators' project for
everyone (`can.ts:195-199`). An application or API named under a project that does not hold it answers
exactly as a missing one (`clients/routes.ts:42-55`, `resources/routes.ts:178-179`). Audit entries for both
store the project as `bucketId` and its team as `ownerGroupId` (`clients/routes.ts:71-73`), presented in the
trail as `projectId` and `ownerTeamId`, which closes the tenant-visibility gap.

## Gotchas

**Only the server writes `bucketId` or `corsOrigins`.** Both are base keys, not registration metadata, so
the wire translation drops them: neither a registration request nor a client metadata document can name the
project it signs people into or grant itself CORS. Every update path carries them forward because no admin
body ever emits `bucketId`. There is no operation that changes an application's project, on any surface.

**CORS must read the stored record, never `Client.find`.** `Client.find` resolves a client metadata
document, so reading origins through it would let an `Origin` header trigger an outbound fetch to a URL the
caller chose. `adapter('Client').find` has no such branch.

**A self-registered application is listed but not managed.** A project's client list includes clients that
registered themselves at its address, but PATCH, secret rotation and DELETE refuse them with 409
(`assertManaged`, `clients/routes.ts:62-69`): they are managed through their registration access token, and
their consent setting must stay what the registration made it. They never block a project's deletion
(`bucketClients(…, true)`, `buckets/routes.ts:243-259`), and they never get machine tokens.

**`findByIndexed` takes only a declared single-field index.** Every adapter calls `assertIndexedField`
(`lib/consts/storage_inventory.ts:953-964`) before it queries, so a listing is never a scan and no
caller-chosen name reaches a query. `findByOwner` was not reused, because the cascade engine reads the owner
fields and a project is not that kind of owner.

**A tenant can no longer have an application on the Default project.** Its team is the System team, so
only a super administrator holds it. The upgrade turned `consent.require` back on for applications that came
from tenant teams' retired projects on the Default project: keeping a tenant's "skip consent" there would
waive consent across the shared population.

## The upgrade

Migration `2026-10-16-remove-projects` (`lib/consts/migrations.ts:1277`, not reversible) reads the retired
projects' area by its literal name, `LEGACY_PROJECTS_AREA` (`:115`, the stored area `projects`). The area is
gone from `STORE_AREAS`, and its collection or table stays on disk, because provisioning never drops
anything. In order, it:

1. refuses, writing nothing, when one client is listed by retired projects on different projects, naming them;
2. writes each listed client's `bucketId` and `corsOrigins` from its retired project, only where absent —
   from the earliest-created retired project when one project has several, reported; ghost ids are
   reported, not written;
3. folds `registeredAtBucket` into `bucketId` and unsets it;
4. gives `admin-panel` and `admin-mcp` the administrators' project (seeds only insert);
5. turns consent back on for the Default-project applications of tenant teams, reported;
6. moves each resource's `projectId` (the retired project's id) to `bucketId` — a resource without a retired
   project gets its namespace when that is a project id, and the Default project otherwise, reported;
7. reports projects where several retired projects declared resources, because machine tokens there now
   widen to every operator-registered application of the project.

Every write is conditional on the target being absent, so a second run writes nothing. The real-database
check is `database/verify_remove_projects.ts`.

## Related

- [[team-ownership]] — the ownership model, now with one kind of container.
- [[container-ownership-transfer]] — moving a project, which carries its applications and APIs by reference.
- [[mcp-server-authorization]] — declared APIs, the resolver rules and machine tokens, keyed by project.
- [[consent-screen-decisions]] — the waiver and the provenance tiers, decided by `clientBelongsToBucket`.
- [[client-registration-attributes]] — why `bucketId` and `corsOrigins` are base keys.
- [[project-is-an-issuer]] — the project as issuer, which is what makes it the natural container.

Verified against [[oauth-server-codebase]].
