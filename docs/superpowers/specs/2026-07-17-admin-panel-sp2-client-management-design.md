# Admin Panel SP-2 — Project-scoped OAuth Client Management

**Status:** Design · **Date:** 2026-07-17 · **Depends on:** SP-1 (admin foundation)

## 0. Context & correction to SP-1

SP-1 built the admin foundation: auth (BFF), RBAC, the `projects` / `userBuckets`
model, and the app shell. It deferred OAuth client management to SP-2.

The SP-1 design sketched SP-2 as **"`projectId` on `Client`"**. That is inconsistent
with the rest of the model: SP-1 deliberately keeps admin-layer foreign keys **off**
the protocol entities — a `User` record carries no `bucketId`/`projectId` (users are
mapped through the bucket, since the collection _is_ the bucket), and the
project→bucket link lives on the project as `Project.bucketId`. Stamping `projectId`
onto the core OIDC `Client` would reintroduce exactly the FK-on-protocol-entity
pattern SP-1 avoided.

**Correction:** the client→project association lives on the **project**, as
`Project.clientIds: string[]`. The protocol `Client` model is unchanged. This spec
also corrects the SP-1 doc's line-24 wording ("clients and users carry a `projectId`")
— neither does; both are mapped from the admin layer.

## 1. Goals & non-goals

### Goals
1. `Project.clientIds: string[]` on the admin-layer project; protocol `Client`
   untouched.
2. Project-scoped client CRUD API under `/admin/api/projects/:id/clients`, reusing
   SP-1 RBAC (`assertProjectAccess`).
3. Secret rotation for confidential clients.
4. Per-project client-management UI (drill-down from the Projects table).
5. Admin-created clients validated through the **same** `validateClient` path as
   dynamic registration.

### Non-goals
- Server-settings editor (SP-4) and JWKS management (SP-5).
- Rich per-bucket auth-method config / end-user CRUD (SP-3).
- Changing the OIDC protocol surface (`/authorize`, `/token`, discovery, registration)
  in any way.

## 2. Data model

Add one field to the admin-layer `Project` (`lib/adapters/types.ts`):

```
Project.clientIds: string[]   // default []
```

- Threaded through `ProjectStoreInstance.create` (optional, default `[]`) and a new
  `update` capability for the field, in **both** the memory and mongodb stores.
- The protocol `Client` collection is unchanged. A project's clients are enumerated
  by loading each id in `clientIds` via `adapter('Client').find` — there is no global
  client `list()` and none is added.

### Invariant: one project per client
A `clientId` appears in **at most one** project's `clientIds` (a client belongs to
exactly one project; 1 project → many clients). There is no FK to enforce this at the
storage layer, so the **admin API enforces it**:
- Create always appends the freshly generated id to exactly one project.
- (There is no cross-project "move" in SP-2; if added later it must remove-then-add
  atomically at the API layer.)
Reverse lookup ("which project owns client X") is a scan over projects — acceptable at
admin scale and not on any hot path.

### Seeding
`ensureAdminSeed` sets the reserved admin project's `clientIds: ['admin-panel']`, so
the panel client is represented through the same mechanism. Existing/other projects
default to `[]`.

## 3. API

All routes are project-nested, guarded by `resolveAdmin` + `assertAuth` +
`assertProjectAccess` (project_admin → only managed projects; super_admin → all).
Client management targets **regular** projects. Errors surface as the SP-1
`admin_error` shape; client-validation failures map to HTTP 422.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/admin/api/projects/:id/clients` | List client summaries for the project (secret never returned). |
| POST   | `/admin/api/projects/:id/clients` | Create: generate `clientId` (+secret if confidential), `validateClient`, `adapter('Client').upsert`, append id to `project.clientIds`. Returns the client; secret returned **once**. |
| GET    | `/admin/api/projects/:id/clients/:clientId` | One client's metadata (secret omitted). 404 if the id is not in this project's `clientIds`. |
| PATCH  | `/admin/api/projects/:id/clients/:clientId` | Update the curated editable fields; re-run `validateClient`. |
| DELETE | `/admin/api/projects/:id/clients/:clientId` | `adapter('Client').destroy` + remove id from `project.clientIds`. |
| POST   | `/admin/api/projects/:id/clients/:clientId/secret` | Rotate the secret (confidential clients); new secret returned **once**. |

**Reserved-client protection:** the `admin-panel` client (in the reserved admin
project) is not manageable through these routes — the routes operate on regular
projects, and any attempt to target `admin-panel` is rejected (mirrors SP-1's
"cannot modify admin project").

**Ownership scoping:** `:clientId` must be present in `:id`'s `clientIds` or the route
404s — a client can never be read/edited via a project that doesn't own it, even by a
super_admin using the wrong project id.

## 4. Editable client fields

A curated subset of client metadata is exposed by the admin UI/API. Everything is
validated by the existing `validateClient`/`assertClientValid`, so admin-created
clients are held to the same rules as dynamically registered ones.

- `client_name`
- `redirect_uris`
- `grant_types` — the full set the **provider currently supports** (discovery
  `grant_types_supported`, feature-flag gated via `hasGrant`): `authorization_code`,
  `refresh_token`, `client_credentials`, device_code, CIBA. The UI offers only grants
  the provider actually enables, so it stays in lockstep with server config.
- `response_types` — derived from the chosen grant types.
- `token_endpoint_auth_method` — `none` (public/PKCE), `client_secret_basic`,
  `client_secret_post`.
- `post_logout_redirect_uris`
- `scope`
- `applicationType` — `web` | `native`
- `consent.require`

`clientId` is generated and immutable. For confidential clients a secret is generated
at creation and on rotation, and returned to the caller **once** (never re-readable via
GET/list).

## 5. UI

Per-project drill-down from the existing Projects table (`lib/admin/ui/pages/`):

- A row action ("Clients") on the Projects table opens a **project Clients view**
  scoped to that project.
- The Clients view is a table: `client_name`, `clientId`, `applicationType`, auth
  method, grant types, with **New / Edit / Delete / Rotate secret** actions.
- Create/Edit is a modal form over the curated fields (§4). On create/rotate, the
  generated secret is shown once in a copyable, dismissible panel with a clear "you
  won't see this again" note.
- There is no global "all clients" page — clients are always viewed through their
  project.

## 6. Testing

Follows SP-1 test patterns (bun:test + eden treaty; memory/Test adapters).

- **Store:** `clientIds` defaults to `[]`; create/update round-trips; admin seed yields
  `['admin-panel']`.
- **Routes:** full CRUD; secret returned once on create and rotate, never on GET/list;
  `validateClient` failure → 422; project_admin can manage clients only in managed
  projects and is denied cross-project (including reading `:clientId` via a
  non-owning project id → 404); `admin-panel` protection; the one-project-per-client
  invariant (a created client appears in exactly one project's `clientIds`).
- **Regression:** existing `/authorize` → `/token` flows for an admin-created client
  work end-to-end (the client is a normal protocol client).

## 7. Out of scope / follow-ups

- Moving a client between projects.
- Bulk import/export of clients.
- Editing the long tail of OIDC client metadata beyond §4 (can be widened later without
  model changes, since storage is the unchanged `Client` collection).
