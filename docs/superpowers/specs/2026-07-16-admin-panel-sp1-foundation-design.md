# Admin Panel — SP-1: Admin Foundation

**Date:** 2026-07-16
**Status:** Design approved, pending spec review
**Sub-project:** SP-1 of the Admin Panel initiative (see "Decomposition" below)

---

## 1. Context & overall vision

OAuth-server.ts currently has no administrative UI. Configuration lives in code
(`lib/configs/application.ts`), clients/users/keys are managed directly in MongoDB,
and there is no notion of tenancy or administrative roles.

The goal is an **admin panel** to configure and operate the server, built around a
two-role, multi-project model:

- **`super_admin`** — sees everything; owns server settings and signing keys.
- **`project_admin`** — manages only the projects assigned to them: their OAuth
  clients and end-users.

**Projects are administratively isolated but share one OAuth runtime.** There is a
single issuer; `/authorize`, `/token`, discovery, and JWKS stay global and
unchanged. "Project" is an admin-layer construct — clients and users carry a
`projectId`, and the admin API/UI enforce who can see what. There are **no**
per-project issuers or token domains.

### Entity hierarchy

```
Project (admin | regular) ──*:1── UserBucket (standalone; own managedBy,
   (has exactly one bucket)        role set, auth-method settings)
                                     └── Users (a physically separate
                                         collection per bucket)
```

- **`UserBucket` is a standalone entity**, not owned by a project. It can be created
  on its own, has its own `managedBy` (owning admins), its own declared role set,
  and its own auth-method settings.
- **A project has exactly one bucket; a bucket may be shared by many projects**
  (one-to-many from bucket to projects). A bucket does not track its projects.
- **Each bucket is its own physical collection** (`user_<bucketId>` in MongoDB / a
  dedicated table in SQL). Users are physically isolated per bucket and never cross
  buckets. This matches the repo's existing `user_<name>` collection scheme.
- Because the collection _is_ the bucket and a bucket may belong to several
  projects, a user record carries **no `bucketId` and no `projectId`**.
- A reserved **`admin` project** always exists, with an "Administrators" bucket
  assigned to it holding the admin accounts (`super_admin` / `project_admin`). Only
  `super_admin` may access the admin project.
- **Regular projects** hold OAuth clients and are assigned exactly one end-user
  bucket.
- **Ownership** is expressed on both entities: `Project.managedBy: userId[]` and
  `UserBucket.managedBy: userId[]`. Both reference users living in the
  Administrators bucket.
- **Roles are defined on the bucket** (`UserBucket.roles: string[]`); a user's
  `roles` must be a subset of its bucket's declared set.
- **The project→bucket assignment** is stored on the project as
  `Project.bucketId: string` (a single bucket); buckets stay project-agnostic.

---

## 2. Decomposition (full initiative)

Each sub-project gets its own spec → plan → build cycle. Order matters — SP-1 is a
hard dependency for the rest.

| ID   | Sub-project                          | Depends on | Notes                                          |
| ---- | ------------------------------------ | ---------- | ---------------------------------------------- |
| SP-1 | **Admin foundation** (this spec)     | —          | Auth, RBAC, project/bucket model, app shell    |
| SP-2 | OAuth client management              | SP-1       | `projectId` on `Client`; project-scoped CRUD   |
| SP-3 | End-user & bucket management         | SP-1       | Rich bucket auth-methods, import/export, users |
| SP-4 | Server-settings editor (super admin) | SP-1       | UI over `ApplicationConfig` via `configStore`  |
| SP-5 | Signing-key (JWKS) management        | SP-1       | View/rotate/retire keys                        |

This document specifies **SP-1 only**.

---

## 3. SP-1 goals & non-goals

### Goals

1. Data model for `projects`, `userBuckets`, and admin `users`, with a seeded
   reserved admin project + bucket.
2. Admin authentication via the server's **own OIDC flow** (the panel is a
   first-party OAuth client). No bespoke auth system.
3. BFF session: tokens held server-side, one httpOnly session cookie to the SPA.
4. RBAC middleware: `super_admin` vs `project_admin`, project-scoped access.
5. Project CRUD + admin-account CRUD (super_admin) + bucket skeleton.
6. React/Ant Design app shell mounted under `/admin/*`, with role-aware nav and
   gated stubs for SP-4/SP-5.
7. First-run setup screen to create the initial `super_admin`.

### Non-goals (deferred)

- OAuth client CRUD (SP-2).
- Rich per-bucket auth-method config (social/domain login), end-user CRUD,
  user import/export (SP-3).
- Server-settings editing and the startup-only-config reload problem (SP-4).
- JWKS management (SP-5).
- Custom end-user role definitions beyond storing the bucket's role set.
- General "client → bucket" binding. SP-1 **special-cases** the reserved admin
  client → admin bucket path only (see §5).

---

## 4. Data model

New/changed collections. Both MongoDB and in-memory adapters implement each store,
per the repo's adapter pattern.

### `projects` (new)

| Field       | Type                   | Notes                                  |
| ----------- | ---------------------- | -------------------------------------- |
| `_id`       | `string` (nanoid)      |                                        |
| `name`      | `string`               |                                        |
| `slug`      | `string`               | unique                                 |
| `type`      | `'admin' \| 'regular'` | exactly one `admin`; cannot be deleted |
| `managedBy` | `string[]`             | admin `userId`s who own the project    |
| `bucketId`  | `string`               | the single bucket assigned (shareable) |
| `createdAt` | `Date`                 |                                        |
| `updatedAt` | `Date`                 |                                        |

Indexes: unique `slug`; `managedBy`; `bucketId`.

### `userBuckets` (new)

Standalone — a bucket is not owned by a project.

| Field         | Type       | Notes                                          |
| ------------- | ---------- | ---------------------------------------------- |
| `_id`         | `string`   | also names the users collection (`user_<_id>`) |
| `name`        | `string`   | e.g. "Administrators", "Dev users"             |
| `managedBy`   | `string[]` | admin `userId`s who own the bucket             |
| `roles`       | `string[]` | role set users in this bucket may hold         |
| `authMethods` | `string[]` | SP-1: `['password']`; full config in SP-3      |
| `createdAt`   | `Date`     |                                                |
| `updatedAt`   | `Date`     |                                                |

Indexes: `managedBy`.

### Bucket user collections (`user_<bucketId>`)

**One collection per bucket**, keeping the repo's existing `user_<name>` scheme
(the `UserStore` constructor already takes a `name`). Users are physically isolated
per bucket. A user record is the existing `User` shape (`_id`, `email`, `verified`,
`password`, `active`, `createdAt`, `updatedAt`, `lastLoginAt`) plus:

| Field   | Type       | Notes                         |
| ------- | ---------- | ----------------------------- |
| `roles` | `string[]` | ⊆ the owning bucket's `roles` |

No `bucketId` (the collection _is_ the bucket) and no `projectId` (a bucket may be
assigned to multiple projects). The existing default `user_redfox` collection
becomes the Administrators bucket's collection during setup, or is left as a legacy
regular bucket — decided in the seed step. End-user login re-partitioning (routing
each client to the right bucket) is completed in SP-3; SP-1 only requires the admin
bucket to resolve for the admin client.

### `adminSession` (new, BFF session store)

| Field               | Type     | Notes                     |
| ------------------- | -------- | ------------------------- |
| `_id`               | `string` | session id (cookie value) |
| `userId`            | `string` |                           |
| `tokens`            | object   | server-side OIDC tokens   |
| `createdAt`         | `Date`   |                           |
| `expiresAt`         | `Date`   | sliding expiry            |
| `absoluteExpiresAt` | `Date`   | hard cap                  |

TTL index on `expiresAt`, mirroring the existing `Session` model pattern.

---

## 5. Authentication (OIDC + BFF)

The admin panel is a **first-party OAuth client** of this server. There is no
separate password-authentication endpoint — authentication is the standard
Authorization Code + PKCE flow.

Seeded at `db:setup` (see §8): the reserved admin OAuth client
(`redirect_uri = <ISSUER>/admin/callback`, trusted first-party so consent is
skipped).

**Login flow:**

1. `GET /admin/login` → redirect to `/authorize` (PKCE, state, nonce).
2. User signs in via the existing login UI, authenticating **against the admin
   bucket**.
3. `GET /admin/callback` → validate state, exchange code for tokens.
4. Store tokens server-side in `adminSession`; set httpOnly, `SameSite=Strict`,
   `Secure` cookie `_admin_session`. The SPA never sees tokens (BFF).
5. `POST /admin/api/logout` → destroy the session row + clear cookie.

**Roles delivery:** the user's `roles` are surfaced as a `roles` claim (ID token /
UserInfo); a `roles` claim is added to the claims config. `resolveAdmin` uses the
session's stored identity + a fresh DB read of the user's `roles` and the projects
they manage.

**Special-cased binding (SP-1 scope boundary):** today `/ui/:uid/login` uses one
default user store with no bucket awareness. SP-1 adds a **minimal hardcoded path**:
the reserved admin client always authenticates against the reserved admin bucket.
The general client→bucket binding is built in SP-2/SP-3.

---

## 6. Authorization (RBAC)

`resolveAdmin()` — Elysia scoped `.derive` that reads `_admin_session`, loads the
session + user, and attaches `{ admin: { userId, roles, projectId } }`. Missing or
invalid session → 401.

Composable guards:

- **`requireAuth`** — valid admin session.
- **`requireRole('super_admin')`** — gates the admin project, server settings
  (SP-4), keys (SP-5), and admin-account management.
- **`requireProjectAccess(projectId)`** — passes if `super_admin`, **or** if
  `admin.userId ∈ project.managedBy`. Every project-scoped route runs this. The
  admin project is never returned to a non-super-admin, even by direct id (→ 403).
- **`requireBucketAccess(bucketId)`** — passes if `super_admin`, **or** if
  `admin.userId ∈ bucket.managedBy`. Gates standalone bucket routes (buckets aren't
  reached through a project).

**Error shape:** admin routes return plain JSON `{ error, message }` with correct
status codes, in their own Elysia error scope — bypassing the OAuth/RFC 6749 error
handler used by protocol endpoints.

---

## 7. API surface (SP-1)

All under `/admin`. `/admin/api/*` is JSON; `/admin/*` (non-api) serves the SPA.

**Auth/session**

- `GET  /admin/login` — redirect to `/authorize`.
- `GET  /admin/callback` — code exchange, session creation.
- `POST /admin/api/logout`.
- `GET  /admin/api/me` — current admin identity, roles, managed project ids.

**Setup (first-run only)**

- `GET  /admin/setup` — serve setup screen **iff** no super_admin exists, else
  redirect to login.
- `POST /admin/api/setup` — create initial super_admin **iff** none exists
  (hard-gated), then redirect to login.

**Projects** (behind `requireAuth`)

- `GET    /admin/api/projects` — scoped list (super → all regular; project_admin →
  where `userId ∈ managedBy`). Admin project never listed to non-super.
- `POST   /admin/api/projects` — **super_admin**; creates project + default bucket;
  sets `managedBy`.
- `GET    /admin/api/projects/:id` — `requireProjectAccess`.
- `PATCH  /admin/api/projects/:id` — `requireProjectAccess`; `managedBy` edits are
  super_admin only.
- `DELETE /admin/api/projects/:id` — **super_admin**.

**Admin accounts** (**super_admin** only; operate within the admin bucket)

- `GET/POST/PATCH/DELETE /admin/api/admins` — create `project_admin` users, set
  `roles`, add/remove them from projects' `managedBy`.

**Buckets** (skeleton — standalone entity)

- `GET  /admin/api/buckets` — scoped list (super → all; project_admin → buckets they
  own via `managedBy`, plus buckets assigned to projects they manage).
- `POST /admin/api/buckets` — create a standalone bucket with name + role set +
  `managedBy`. Creates the backing `user_<bucketId>` collection lazily.
- `PUT /admin/api/projects/:id/bucket` — set the project's single bucket
  (`Project.bucketId = bucketId`, replacing any previous); `requireProjectAccess` +
  bucket ownership. The same bucket may be set on many projects.

Rich auth-method config + user import/export deferred to SP-3.

---

## 8. Bootstrap & seeding

`bun run db:setup` (`database/mongodb.ts`) seeds, idempotently:

1. The reserved `admin` project (`type: 'admin'`).
2. Its "Administrators" bucket (`roles: ['super_admin', 'project_admin']`,
   `authMethods: ['password']`).
3. The reserved admin OAuth client (`redirect_uri = <ISSUER>/admin/callback`).

No super_admin user is seeded. On first visit to `/admin`, if no super_admin exists,
the panel serves a **one-time setup screen** to create the initial super_admin
(email + password, `Bun.password`-hashed). The setup route is hard-gated: once any
super_admin exists it returns 404 / redirects to login, so it cannot mint rogue
admins later.

---

## 9. UI shell (React 19 + Ant Design 6)

- New SPA entry `lib/admin/ui/adminClient.tsx`, bundled to `public/admin.js`; add an
  `admin` target to the `build` and `watch` scripts alongside `loginClient.tsx`.
- Server render of the shell HTML + hydration, following the existing
  `interactions/serverRender.tsx` pattern.
- Pages: **Setup** (first-run), **Login** landing (redirect), **Layout** with a
  role-aware sidebar, **Projects** (list + create/edit, `managedBy` assignment for
  super), **Admins** (super only). **Settings** and **Keys** appear as gated
  "coming soon" stubs so nav is complete (filled in SP-4/SP-5).
- `project_admin` sees only their projects and no admin-only sections.

---

## 10. Module layout

```
lib/admin/
  index.ts            ← Elysia plugin, mounts /admin/*
  auth/
    session.ts        ← BFF session create/verify/destroy
    login.ts          ← /admin/login, /admin/callback, logout
    setup.ts          ← first-run super_admin creation (hard-gated)
    rbac.ts           ← resolveAdmin + requireRole / requireProjectAccess
  projects/{routes,schema}.ts
  users/{routes,schema}.ts        ← admin-account CRUD (super_admin)
  buckets/{routes,schema}.ts      ← skeleton
  ui/
    adminClient.tsx   ← SPA entry (→ public/admin.js)
    serverRender.tsx
    pages/            ← Setup, Layout, Projects, Admins, Settings/Keys stubs
lib/adapters/
  types.ts            ← + ProjectStore, UserBucketStore, AdminSessionStore; User + roles
  mongodb/            ← projectStore.ts, userBucketStore.ts, adminSessionStore.ts;
                        userStore.ts keyed by bucketId (existing `name` = bucketId)
  memory/             ← same, in-memory
database/
  collections.ts      ← + 'projects', 'userBuckets', 'adminSession'
                        (per-bucket `user_<id>` collections are created lazily, as
                         `user_redfox` is today — not in the static list)
  mongodb.ts          ← seed admin project + Administrators bucket + panel client
```

Admin routes are excluded from the OIDC discovery document.

---

## 11. Testing

Bun's native test runner + Chai + Sinon + the Eden type-safe client, per repo
conventions. `test/admin/admin.config.ts` bootstraps the provider and seeds the
admin project/bucket/super_admin + panel client; memory adapters back
`projects`/`userBuckets`/`adminSession`.

Coverage:

- OIDC login → callback → BFF session established; logout destroys it.
- `resolveAdmin`: no/invalid/expired session → 401.
- RBAC: super vs project_admin; admin project hidden even by direct id → 403;
  project-scoped list returns only owned projects.
- Project CRUD + `managedBy` assignment; super-only guards enforced.
- First-run setup creates super_admin; second attempt is hard-gated.
- Seed idempotency (`db:setup` twice is a no-op).

---

## 12. Risks & open questions

- **Login-flow coupling:** SP-1 touches `/ui/:uid/login` and the claims config, not
  just new admin routes, because of the special-cased admin client→bucket path.
  Contained, but not zero-risk — must not regress existing end-user login. Covered
  by keeping the change additive and running the full suite.
- **Per-bucket collections:** one `user_<bucketId>` collection per bucket reuses the
  existing `user_<name>` scheme, so no cross-collection user migration is needed.
  The cost is many collections at scale and no single-query "all users" — acceptable
  given physical bucket isolation is a deliberate requirement.
- **Cross-collection user id references:** `managedBy` (on both projects and
  buckets) references users in the Administrators bucket collection; resolving an
  arbitrary user globally requires knowing its bucket. SP-1 only references admin
  users, so a bare `userId` resolved against the admin bucket is sufficient.
- **Project→bucket (one bucket per project, shareable):** stored as
  `Project.bucketId`. Deleting a bucket that projects still reference must be
  blocked or cascade-checked. "Which projects use bucket X" is an indexed query on
  `bucketId`.
- **`roles` claim exposure:** ensure the `roles` claim is only issued to the
  first-party admin client, not leaked to arbitrary clients.
