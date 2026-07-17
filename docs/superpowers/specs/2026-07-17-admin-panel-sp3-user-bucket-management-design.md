# Admin Panel SP-3 — End-User & Bucket Management

**Status:** Design · **Date:** 2026-07-17 · **Depends on:** SP-1 (admin foundation), SP-2 (client management)

## 0. Context

SP-1 built the admin foundation (auth/BFF, RBAC, the `projects` / `userBuckets`
model, app shell) and seeded the reserved admin project + Administrators bucket.
SP-2 added project-scoped OAuth client management via `Project.clientIds`.

Two pieces were explicitly deferred to SP-3:

1. **End-user & bucket management** — there is no admin surface for the end-users
   living in a bucket's `user_<bucketId>` collection, and the bucket routes are a
   skeleton (list, create, delete) with no edit and no user management.
2. **General client→bucket login routing** — SP-1 special-cased *only* the admin
   client → admin bucket in `lib/interactions/index.ts`; every other client falls
   back to the default `redfox` user store. SP-1 §5 named "route each client to the
   right bucket" as SP-3 work.

The data to complete routing is now all present: a client belongs to a project
(`Project.clientIds`, SP-2) and a project points at one bucket (`Project.bucketId`,
SP-1).

## 1. Goals & non-goals

### Goals
1. End-user CRUD per bucket: list, create, edit (roles/active), reset password,
   deactivate, and hard delete.
2. Bucket editing: `name`, `roles`, and (super-only) `managedBy`; plus a single-bucket
   GET for the detail page.
3. Complete client→bucket login routing behind a clean, indexable interface, with a
   safe fallback that preserves existing end-user login.
4. A top-level **Buckets** UI section (canonical) plus a **Users** shortcut on the
   Projects table that deep-links into the owning project's bucket.
5. Seed a manageable `redfox` bucket record so legacy default-collection users are
   visible in the UI.

### Non-goals (deferred to later SPs)
- **Rich auth-methods** — social/IdP federation (Google/GitHub) and domain-restricted
  login. `UserBucket.authMethods` stays stored but **not editable** in SP-3 (remains
  `['password']`). This is a protocol-federation subsystem and gets its own SP.
- **Bulk import/export** of users (CSV/JSON).
- Any change to the OIDC protocol surface beyond the single login-routing lookup
  (`/authorize`, `/token`, discovery, registration, claims are otherwise untouched).
- Custom end-user role *definitions* beyond the bucket's declared `roles` set.

## 2. Data model

No field changes to `User` or `UserBucket` — both already carry everything needed
(`User`: `_id/email/verified/password/active/roles/timestamps`; `UserBucket`:
`name/managedBy/roles/authMethods`). Two **store-interface** additions only, each
implemented in **both** the memory and mongodb adapters:

- `UserStoreInstance.destroy(id: string): Promise<void>` — hard-delete a user row
  from the bucket's `user_<bucketId>` collection.
- `ProjectStoreInstance.findByClientId(clientId: string): Promise<Project | null>` —
  reverse lookup. Memory adapter scans projects for `clientIds.includes(clientId)`;
  mongodb adapter queries `{ clientIds: clientId }` (index-ready). Returns the first
  match (the one-project-per-client invariant from SP-2 guarantees at most one).

### Authorization refinement (two bucket-access levels)

SP-1's `assertBucketAccess(admin, bucket)` grants access only when `super_admin` **or**
`admin.userId ∈ bucket.managedBy`. That is too narrow for SP-3: a project_admin who
manages a *project* backed by a bucket (but is not in that bucket's `managedBy`) still
needs to reach the bucket to manage its end-users — and the Projects→Users shortcut
(§7) deep-links exactly that user into the bucket. SP-3 therefore distinguishes two
levels:

- **`assertBucketAccess` (existing, strict — super OR `bucket.managedBy`)** — reused
  only for **mutating the bucket entity itself** (`PATCH`/`DELETE /admin/api/buckets/:id`).
  Editing a bucket's `name`/`roles`/`managedBy` affects every project sharing it, so it
  stays restricted to bucket owners and super_admins.
- **`assertBucketUserAccess(admin, bucket)` (new, broader — super OR `bucket.managedBy`
  OR the admin manages a project whose `bucketId === bucket._id`)** — for **reading the
  bucket detail and managing its end-users** (`GET /admin/api/buckets/:id` and every
  `.../users` route). It resolves the project-backing case by checking the caller's
  managed projects (`AdminContext.managedProjectIds`, already populated by
  `resolveAdmin`) against the projects' `bucketId`s via the project store. It is
  `async` (it may load projects); routes `await` it.

## 3. Login routing (protocol-touching)

New helper `lib/admin/auth/resolveBucket.ts`:

```
resolveBucketForClient(clientId: string): Promise<string>
  1. clientId === ADMIN_CLIENT_ID → ADMIN_BUCKET_ID   (SP-1 special case, centralized)
  2. project = await findByClientId(clientId); project?.bucketId → that bucketId
  3. otherwise → 'redfox'                              (default fallback)
```

`lib/interactions/index.ts` login POST (currently lines 152–155) replaces the
hardcoded admin-only branch with a single `resolveBucketForClient(clientId)` call,
then `getUserStore(bucketId)` as today. Nothing else in the login/consent/resume flow
changes. The `findAccount`/claims path (`lib/addon/account.ts`) is untouched — it
still returns `{ sub }`, so account resolution needs no bucket awareness.

**Risk & mitigation:** this is the one protocol-touching change. The `redfox`
fallback keeps every currently-unassigned client (the standard test client,
dynamically-registered clients) authenticating exactly as before. The full test suite
must stay green, plus an explicit end-to-end `/authorize`→`/token` regression test
(§7).

## 4. Seeding

`ensureAdminSeed` (`lib/admin/seed.ts`) additionally ensures a `redfox` `UserBucket`
record exists, idempotently, alongside the existing admin seed:

```
{ _id: 'redfox', name: 'Default users', managedBy: [], roles: [],
  authMethods: ['password'] }
```

This makes the pre-existing `user_redfox` collection's users visible and manageable in
the Buckets UI. Creating the record does not move or migrate any user rows — the
collection already exists and is unchanged. `roles: []` reflects that legacy users
carry no declared role set; a super_admin can widen it via the bucket editor.

## 5. API surface

All routes under `/admin/api`, guarded by `resolveAdmin` + `assertAuth`, using the
SP-1 `admin_error` JSON error shape. Passwords are **never** returned by any route.

### Buckets (extend `lib/admin/buckets/`)

| Method | Path | Guard | Purpose |
| ------ | ---- | ----- | ------- |
| GET    | `/admin/api/buckets/:id`        | `assertBucketUserAccess` | One bucket (detail page). |
| PATCH  | `/admin/api/buckets/:id`        | `assertBucketAccess` (strict); `managedBy` edits **super_admin only** | Edit `name`, `roles`, `managedBy`. |

Existing `GET /admin/api/buckets`, `POST /admin/api/buckets`, `DELETE
/admin/api/buckets/:id` are unchanged. Note the split: **reading** a bucket detail uses
the broader `assertBucketUserAccess` (so a project_admin managing a backing project can
open it), while **editing the bucket entity** uses the strict `assertBucketAccess`.

### End-users (new `lib/admin/users-end/`)

Kept as a **separate module** from `lib/admin/users/` (which manages admin *accounts*
in the reserved admin bucket) to keep each file single-purpose. All routes are
bucket-nested and guarded by `assertBucketUserAccess(:id)` — a project_admin can reach
buckets they own **or** that back a project they manage; any other bucket is denied.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/admin/api/buckets/:id/users` | List users, password stripped. |
| POST   | `/admin/api/buckets/:id/users` | Create: `email` + initial `password` + `roles`. `roles ⊆ bucket.roles`; `verified:true`, `active:true`. Password `Bun.password`-hashed. 409 on duplicate email. |
| PATCH  | `/admin/api/buckets/:id/users/:uid` | Edit `roles` (⊆ bucket.roles) and/or `active`. |
| POST   | `/admin/api/buckets/:id/users/:uid/password` | Reset password: admin supplies the new password, `Bun.password`-hashed. |
| DELETE | `/admin/api/buckets/:id/users/:uid` | Hard delete (`UserStore.destroy`). |

**Role validation:** any create/edit whose `roles` is not a subset of the bucket's
declared `roles` → HTTP 422 (`admin_error`).

**Reserved-bucket protection:** the reserved admin bucket (`ADMIN_BUCKET_ID`) is
**off-limits to every SP-3 generic route** — `GET`/`PATCH /admin/api/buckets/:id` and
all `.../users` routes reject `:id === ADMIN_BUCKET_ID` (→ 403, mirroring SP-2's
"cannot modify the admin project"). Admin accounts are managed **exclusively** through
SP-1's `/admin/api/admins` routes (super_admin only), which enforce the
last-active-super_admin guard. This is a hard block, not a convention: it closes any
path that could mutate `user_admin` outside the guarded admin-account surface. The
admin bucket is also **excluded from `GET /admin/api/buckets`** so it never appears in
the Buckets section (it is represented on the Admins page instead).

## 6. Editable fields

- **Bucket:** `name`, `roles` (add/remove), `managedBy` (super-only).
- **End-user:** `email` (create only; immutable after), `roles` (⊆ bucket.roles),
  `active`, `password` (create + reset). `verified` defaults `true` on admin-create.
  `_id`, timestamps, `lastLoginAt` are system-managed.

**Role-set shrink:** removing a role from a bucket while some users still hold it is
**allowed** (not blocked). Existing user assignments are left as-is; the user-edit UI
simply stops offering the removed role, and a subsequent PATCH that includes it would
fail the subset check. This avoids a blocking cross-collection scan on every bucket
edit; the mild inconsistency (a user retaining a role no longer declared) is cosmetic
and self-heals on the next edit.

## 7. UI (`lib/admin/ui/pages/`)

- **Buckets** — new sidebar nav item + list page. Scoped: super_admin → all regular
  buckets; project_admin → buckets they own (`managedBy`) or that back a project they
  manage. The reserved admin bucket is never listed (managed via the Admins page).
  Columns: name, roles, # projects using it. New-bucket action stays super-only
  (existing POST guard).
- **BucketDetail** — header with editable `name` and `roles` (and `managedBy` for
  super), followed by a **Users** table: email, roles, active, verified, with **New /
  Edit / Reset password / Deactivate / Delete** actions. Create/Edit are modal forms;
  roles are checkboxes sourced from `bucket.roles`. Reset-password and Delete confirm
  before acting.
- **Projects** table gains a **Users** row action that deep-links to the project's
  `bucketId` BucketDetail page; disabled/hidden when `bucketId` is null. This is a
  navigation shortcut only — the BucketDetail page is the single source of truth
  (edits there affect the shared bucket, as expected).

The `authMethods` field is **not** surfaced for editing in SP-3 (deferred with the
rich-auth work); if shown at all it is read-only.

## 8. Module layout

```
lib/admin/
  buckets/{routes,schema}.ts     ← + GET :id, PATCH :id
  users-end/{routes,schema}.ts   ← NEW: end-user CRUD (separate from users/ admin-accounts)
  auth/resolveBucket.ts          ← NEW: resolveBucketForClient
  auth/rbac.ts                   ← + assertBucketUserAccess (broad, project-backing aware)
  seed.ts                        ← + ensure redfox bucket
  index.ts                       ← mount users-end routes
  ui/pages/
    Buckets.tsx                  ← NEW: list
    BucketDetail.tsx             ← NEW: bucket editor + users table
    Projects.tsx                 ← + "Users" row action
    Layout.tsx                   ← + Buckets nav item
lib/adapters/
  types.ts                       ← + UserStore.destroy, ProjectStore.findByClientId
  memory/{userStore,projectStore}.ts    ← implement both
  mongodb/{userStore,projectStore}.ts   ← implement both (mongo findByClientId indexable)
lib/interactions/index.ts        ← login POST uses resolveBucketForClient
```

## 9. Testing

Bun's native test runner + Chai + Sinon + the Eden type-safe client, per repo
conventions and the SP-1/SP-2 test patterns; memory/Test adapters back the stores.

- **Store:** `UserStore.destroy` round-trip (create → find → destroy → find null);
  `ProjectStore.findByClientId` hit and miss in both adapters.
- **Routing:** `resolveBucketForClient` — admin client → admin bucket; a client
  assigned to a regular project → that project's bucket; an unassigned client →
  `redfox`. **Regression:** an end-to-end `/authorize` → `/token` flow for a normal
  (unassigned) client still succeeds unchanged.
- **Bucket routes:** GET one; PATCH edits `name`/`roles`; `managedBy` edit rejected
  for project_admin, allowed for super. Access levels: a project_admin who owns the
  bucket **or** manages a project backed by it can GET it; the strict `assertBucketAccess`
  on PATCH denies a project_admin who only has project-backing access (they can view
  and manage users but not mutate the shared bucket entity).
- **End-user routes:** full CRUD; password never present in list/get/create/patch
  responses; `roles ⊄ bucket.roles` → 422; duplicate email on create → 409; hard
  delete removes the row; reset-password changes the stored hash. **Access:** a
  project_admin can manage users in a bucket they own **and** in a bucket backing a
  project they manage (`assertBucketUserAccess`); a bucket they neither own nor reach
  via a managed project is denied.
- **Reserved admin bucket:** `GET`/`PATCH /admin/api/buckets/admin` and every
  `/admin/api/buckets/admin/users` route reject the reserved bucket (→ 403) even for a
  super_admin; the admin bucket does not appear in `GET /admin/api/buckets`; admin
  accounts remain manageable only via `/admin/api/admins`.
- **Seed:** `redfox` bucket created idempotently (`ensureAdminSeed` twice is a no-op),
  and does not disturb existing `user_redfox` rows.

## 10. Risks & open questions

- **Login-flow coupling (primary risk):** the routing change edits the shared
  `/ui/:uid/login` handler. Contained to a single helper call with a preserved
  fallback, and covered by the regression test above, but must not regress existing
  end-user login.
- **Shared-bucket edits:** editing a bucket that several projects point at affects all
  of them. This is inherent to the standalone-bucket model; the canonical BucketDetail
  page (not the per-project shortcut) is where edits happen, making the shared nature
  visible.
- **Role-set shrink inconsistency:** documented in §6 — allowed by design, self-heals
  on next user edit.
```