# Admin Panel SP-3 — End-User & Bucket Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Manage end-users per bucket from the admin panel, edit buckets, and complete client→bucket login routing so every OAuth client authenticates against its project's bucket (falling back to the default `redfox` bucket).

**Architecture:** End-users live in per-bucket `user_<bucketId>` collections (existing scheme). The admin panel gains a top-level Buckets section (list → bucket detail with a users table) plus a Users shortcut on the Projects table. Login resolves a client to its bucket via a new `resolveBucketForClient` helper backed by `ProjectStore.findByClientId`; unassigned clients keep using `redfox`. The reserved admin bucket is hard-blocked from all SP-3 generic routes — admin accounts stay on SP-1's `/admin/api/admins` surface.

**Tech Stack:** Bun, Elysia, TypeBox, MongoDB + memory adapters, React 19 + Ant Design 6, bun:test + Eden treaty.

## Global Constraints

- Protocol surface (`/authorize`, `/token`, discovery, `/reg`, claims/`findAccount`) is unchanged except the single bucket-resolution lookup in `POST ui/:uid/login`.
- The reserved admin bucket (`ADMIN_BUCKET_ID = 'admin'`) is **off-limits** to every SP-3 generic bucket/user route (→ 403), excluded from `GET /admin/api/buckets`, and never listed in the Buckets UI. Admin accounts are managed only via `/admin/api/admins`.
- An unassigned client (belongs to no project) authenticates against the default `'redfox'` bucket — preserves existing end-user login and the test suite.
- A user's `roles` must be a subset of its bucket's `roles`; violations → HTTP 422.
- Passwords are never returned by any route (list/get/create/patch strip `password`).
- Two bucket-access levels: **`assertBucketAccess`** (existing, strict: super OR `bucket.managedBy`) gates mutating the bucket entity (PATCH); **`assertBucketUserAccess`** (new, broad: super OR `bucket.managedBy` OR the caller manages a project whose `bucketId` is this bucket) gates reading the bucket detail and managing its users.
- `authMethods` is stored but NOT editable in SP-3 (deferred with rich-auth work).
- Follow SP-1/SP-2 patterns exactly: `AdminError` + `admin_error` shape, `resolveAdmin`/`assertAuth`, memory + mongodb store parity, `bun test`. TDD, DRY, YAGNI, one commit per task.

---

### Task 1: Store layer — `UserStore.destroy` + `ProjectStore.findByClientId`

**Files:**
- Modify: `lib/adapters/types.ts` (`UserStoreInstance`, `ProjectStoreInstance`)
- Modify: `lib/adapters/memory/userStore.ts`, `lib/adapters/mongodb/userStore.ts`
- Modify: `lib/adapters/memory/projectStore.ts`, `lib/adapters/mongodb/projectStore.ts`
- Test: append to `test/admin/user_store.spec.ts` and `test/admin/project_store.spec.ts`

**Interfaces:**
- Produces: `UserStoreInstance.destroy(id: string): Promise<void>`; `ProjectStoreInstance.findByClientId(clientId: string): Promise<Project | null>`.

- [ ] **Step 1: Write the failing tests.**

Append to `test/admin/user_store.spec.ts` (inside the existing `describe`):
```ts
	it('hard-deletes a user', async () => {
		const u = await store.create('del@x.io', 'hash');
		expect(await store.find(u._id)).not.toBeNull();
		await store.destroy(u._id);
		expect(await store.find(u._id)).toBeNull();
	});
```

Append to `test/admin/project_store.spec.ts` (mirror the file's existing imports; it already imports `getProjectStore`):
```ts
	it('finds a project by one of its client ids', async () => {
		const store = getProjectStore();
		const p = await store.create({
			name: 'FB',
			slug: `fb-${Math.random()}`,
			clientIds: ['cid-123']
		});
		const found = await store.findByClientId('cid-123');
		expect(found?._id).toBe(p._id);
		expect(await store.findByClientId('nope')).toBeNull();
	});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test test/admin/user_store.spec.ts test/admin/project_store.spec.ts`
Expected: FAIL (`store.destroy` / `store.findByClientId` are not functions).

- [ ] **Step 3: Implement — types.** In `lib/adapters/types.ts`:

Add to `UserStoreInstance` (after `update`):
```ts
	destroy(id: string): Promise<void>;
```
Add to `ProjectStoreInstance` (after `listByManager`):
```ts
	findByClientId(clientId: string): Promise<Project | null>;
```

- [ ] **Step 4: Implement — memory stores.**

In `lib/adapters/memory/userStore.ts`, add after `update`:
```ts
	async destroy(_id: string): Promise<void> {
		this.users.delete(_id);
	}
```
In `lib/adapters/memory/projectStore.ts`, add after `listByManager`:
```ts
	async findByClientId(clientId: string): Promise<Project | null> {
		for (const p of this.projects.values()) {
			if (p.clientIds.includes(clientId)) return p;
		}
		return null;
	}
```

- [ ] **Step 5: Implement — mongodb stores.**

In `lib/adapters/mongodb/userStore.ts`, add after `update`:
```ts
	async destroy(_id: string): Promise<void> {
		await db.collection<User>(this.prefix + this.name).deleteOne({ _id });
	}
```
In `lib/adapters/mongodb/projectStore.ts`, add after `listByManager`:
```ts
	async findByClientId(clientId: string): Promise<Project | null> {
		return this.collection.findOne({ clientIds: clientId });
	}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `bun test test/admin/user_store.spec.ts test/admin/project_store.spec.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add lib/adapters/types.ts lib/adapters/memory/userStore.ts lib/adapters/mongodb/userStore.ts lib/adapters/memory/projectStore.ts lib/adapters/mongodb/projectStore.ts test/admin/user_store.spec.ts test/admin/project_store.spec.ts
git commit -m "feat(admin): UserStore.destroy + ProjectStore.findByClientId"
```

---

### Task 2: `resolveBucketForClient` + wire into login

**Files:**
- Create: `lib/admin/auth/resolveBucket.ts`
- Modify: `lib/interactions/index.ts` (login POST bucket resolution + imports)
- Test: create `test/admin/resolve_bucket.spec.ts`

**Interfaces:**
- Consumes: `ProjectStore.findByClientId` (Task 1); `ADMIN_CLIENT_ID`, `ADMIN_BUCKET_ID` from `lib/admin/consts.js`; `getProjectStore` from `lib/adapters/index.js`.
- Produces: `resolveBucketForClient(clientId: string | undefined): Promise<string>` — returns `ADMIN_BUCKET_ID` for the admin client, the owning project's `bucketId` for an assigned client, else `'redfox'`.

- [ ] **Step 1: Write the failing test.** Create `test/admin/resolve_bucket.spec.ts`:

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { resolveBucketForClient } from 'lib/admin/auth/resolveBucket.ts';
import { getProjectStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

describe('resolveBucketForClient', () => {
	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('routes the admin client to the admin bucket', async () => {
		expect(await resolveBucketForClient(ADMIN_CLIENT_ID)).toBe(ADMIN_BUCKET_ID);
	});

	it('routes an assigned client to its project bucket', async () => {
		await getProjectStore().create({
			name: 'P',
			slug: `p-${Math.random()}`,
			bucketId: 'devs',
			clientIds: ['app-1']
		});
		expect(await resolveBucketForClient('app-1')).toBe('devs');
	});

	it('falls back to redfox for an unassigned or missing client', async () => {
		expect(await resolveBucketForClient('unknown')).toBe('redfox');
		expect(await resolveBucketForClient(undefined)).toBe('redfox');
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/resolve_bucket.spec.ts`
Expected: FAIL (`lib/admin/auth/resolveBucket.ts` does not exist).

- [ ] **Step 3: Implement the helper.** Create `lib/admin/auth/resolveBucket.ts`:

```ts
import { getProjectStore } from '../../adapters/index.js';
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from '../consts.js';

// Resolve which user bucket a client authenticates against at login time.
//   1. the reserved admin client → the admin bucket
//   2. a client assigned to a project → that project's bucket
//   3. otherwise → the default 'redfox' bucket (unassigned/dynamic clients)
export async function resolveBucketForClient(
	clientId: string | undefined
): Promise<string> {
	if (clientId === ADMIN_CLIENT_ID) return ADMIN_BUCKET_ID;
	if (clientId) {
		const project = await getProjectStore().findByClientId(clientId);
		if (project?.bucketId) return project.bucketId;
	}
	return 'redfox';
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/resolve_bucket.spec.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire into the login handler.** In `lib/interactions/index.ts`:

Change the import on line 37 (drop the now-unused admin consts, add the helper):
```ts
import { resolveBucketForClient } from 'lib/admin/auth/resolveBucket.js';
```
(Remove the old `import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from 'lib/admin/consts.js';` line — both become unused here.)

In the `POST 'ui/:uid/login'` handler, replace the current bucket-resolution block:
```ts
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			const bucketId =
				clientId === ADMIN_CLIENT_ID ? ADMIN_BUCKET_ID : undefined;
			const userStore = getUserStore(bucketId);
```
with:
```ts
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			const bucketId = await resolveBucketForClient(clientId);
			const userStore = getUserStore(bucketId);
```

- [ ] **Step 6: Run the login-routing regression suite**

Run: `bun test test/admin/interactions_bucket.spec.ts`
Expected: PASS (4 tests) — admin client → admin bucket, `regular-app` (unassigned) → redfox, both still work.

- [ ] **Step 7: Commit**

```bash
git add lib/admin/auth/resolveBucket.ts lib/interactions/index.ts test/admin/resolve_bucket.spec.ts
git commit -m "feat(admin): route login to the client's project bucket"
```

---

### Task 3: Seed the manageable `redfox` bucket

**Files:**
- Modify: `lib/admin/seed.ts`
- Test: append to `test/admin/seed.spec.ts`

**Interfaces:**
- Produces: after `ensureAdminSeed()`, a `UserBucket` with `_id: 'redfox'` exists.

- [ ] **Step 1: Write the failing test.** Append to `test/admin/seed.spec.ts` (mirror its existing imports; it imports `ensureAdminSeed` and `getBucketStore`):
```ts
	it('seeds a manageable default (redfox) bucket', async () => {
		await ensureAdminSeed();
		const bucket = await getBucketStore().find('redfox');
		expect(bucket?.name).toBe('Default users');
		expect(bucket?.authMethods).toEqual(['password']);
	});
```
If `getBucketStore` is not already imported in the file, add it to the `lib/adapters/index.ts` import.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/seed.spec.ts -t "redfox"`
Expected: FAIL (`bucket` is null).

- [ ] **Step 3: Implement.** In `lib/admin/seed.ts`, inside `ensureAdminSeed`, right after the existing admin-bucket `if (!(await buckets.find(ADMIN_BUCKET_ID))) { ... }` block, add:
```ts
	if (!(await buckets.find('redfox'))) {
		await buckets.create({
			_id: 'redfox',
			name: 'Default users',
			managedBy: [],
			roles: [],
			authMethods: ['password']
		});
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/seed.spec.ts`
Expected: PASS (all seed tests, including idempotency).

- [ ] **Step 5: Commit**

```bash
git add lib/admin/seed.ts test/admin/seed.spec.ts
git commit -m "feat(admin): seed a manageable default (redfox) bucket"
```

---

### Task 4: Bucket detail routes (GET/PATCH) + `assertBucketUserAccess` + reserved-bucket protection

**Files:**
- Modify: `lib/admin/auth/rbac.ts` (add `assertBucketUserAccess`)
- Create: `lib/admin/buckets/access.ts` (shared bucket loaders)
- Modify: `lib/admin/buckets/routes.ts` (GET `:id`, PATCH `:id`, list excludes admin bucket)
- Modify: `lib/admin/buckets/schema.ts` (add `UpdateBucketBody`)
- Test: append to `test/admin/buckets_routes.spec.ts`

**Interfaces:**
- Produces:
  - `assertBucketUserAccess(admin: AdminContext, bucket: UserBucket): Promise<void>` in `rbac.ts`.
  - `loadBucketForUsers(admin, id): Promise<UserBucket>` and `loadBucketForEdit(admin, id): Promise<UserBucket>` in `buckets/access.ts` — both reject the reserved admin bucket (403) and 404 a missing bucket; `ForUsers` uses `assertBucketUserAccess`, `ForEdit` uses strict `assertBucketAccess`.
  - `UpdateBucketBody` in `buckets/schema.ts`.
- Consumes: `assertBucketAccess`, `AdminError`, `getBucketStore`, `getProjectStore`, `ADMIN_BUCKET_ID`.

- [ ] **Step 1: Write the failing tests.** Append to `test/admin/buckets_routes.spec.ts` inside the `describe('buckets API', ...)` block. (Add `getProjectStore` — already imported — and reuse the file's `sessionCookieFor`/`superCookie` helpers.)
```ts
	it('gets and patches a bucket (name + roles)', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Editable', roles: ['viewer'] },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const got = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie } });
		expect((got.data as UserBucket).name).toBe('Editable');
		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'Renamed', roles: ['viewer', 'editor'] }, { headers: { cookie } });
		expect((patched.data as UserBucket).name).toBe('Renamed');
		expect((patched.data as UserBucket).roles).toEqual(['viewer', 'editor']);
	});

	it('lets a project_admin read a bucket backing a project they manage', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		// bucket NOT owned by pa (managedBy empty)
		const created = await client.admin.api.buckets.post(
			{ name: 'Backing' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = created.data as UserBucket;
		// a project pa manages points at it
		const proj = await getProjectStore().create({
			name: 'PB',
			slug: `pb-${Math.random()}`,
			managedBy: [pa.userId]
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const got = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: pa.cookie } });
		expect(got.status).toBe(200);
	});

	it('forbids a project_admin from editing a bucket they only reach via a project', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'BackingRO' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = created.data as UserBucket;
		const proj = await getProjectStore().create({
			name: 'PB2',
			slug: `pb2-${Math.random()}`,
			managedBy: [pa.userId]
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'nope' }, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('rejects managing the reserved admin bucket', async () => {
		const cookie = await superCookie();
		const got = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie } });
		expect(got.status).toBe(403);
		const list = await client.admin.api.buckets.get({ headers: { cookie } });
		expect((list.data as UserBucket[]).some((b) => b._id === ADMIN_BUCKET_ID)).toBe(false);
	});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test test/admin/buckets_routes.spec.ts`
Expected: FAIL (no GET `:id` / PATCH routes; admin bucket currently listed).

- [ ] **Step 3: Implement `assertBucketUserAccess`.** In `lib/admin/auth/rbac.ts`, add after `assertBucketAccess`:
```ts
// Broader than assertBucketAccess: also grants access when the caller manages a
// project whose bucketId is this bucket (so a project_admin can manage the users of
// a bucket backing their project without owning the bucket). Used for reading a
// bucket's detail and managing its end-users — NOT for editing the bucket entity.
export async function assertBucketUserAccess(
	admin: AdminContext,
	bucket: UserBucket
): Promise<void> {
	if (admin.roles.includes('super_admin')) return;
	if (bucket.managedBy.includes(admin.userId)) return;
	const managed = await getProjectStore().listByManager(admin.userId);
	if (managed.some((p) => p.bucketId === bucket._id)) return;
	throw new AdminError(403, 'no access to this bucket');
}
```
(`getProjectStore` and the `UserBucket` type are already imported in `rbac.ts`.)

- [ ] **Step 4: Implement the shared loaders.** Create `lib/admin/buckets/access.ts`:
```ts
import { getBucketStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	AdminError,
	assertBucketAccess,
	assertBucketUserAccess,
	type AdminContext
} from '../auth/rbac.js';

function assertNotReserved(id: string): void {
	if (id === ADMIN_BUCKET_ID) {
		throw new AdminError(403, 'the admin bucket is managed via /admin/api/admins');
	}
}

// Load a bucket for reading detail / managing its users (broad access).
export async function loadBucketForUsers(
	admin: AdminContext,
	id: string
): Promise<UserBucket> {
	assertNotReserved(id);
	const bucket = await getBucketStore().find(id);
	if (!bucket) throw new AdminError(404, 'bucket not found');
	await assertBucketUserAccess(admin, bucket);
	return bucket;
}

// Load a bucket for mutating the bucket entity itself (strict access).
export async function loadBucketForEdit(
	admin: AdminContext,
	id: string
): Promise<UserBucket> {
	assertNotReserved(id);
	const bucket = await getBucketStore().find(id);
	if (!bucket) throw new AdminError(404, 'bucket not found');
	assertBucketAccess(admin, bucket);
	return bucket;
}
```

- [ ] **Step 5: Add the update schema.** In `lib/admin/buckets/schema.ts`, add:
```ts
export const UpdateBucketBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String()))
});
```

- [ ] **Step 6: Add GET/PATCH + exclude admin bucket from list.** In `lib/admin/buckets/routes.ts`:

Extend the imports:
```ts
import { ADMIN_BUCKET_ID } from '../consts.js';
import { loadBucketForUsers, loadBucketForEdit } from './access.js';
import { CreateBucketBody, UpdateBucketBody } from './schema.js';
```
(Replace the existing `import { CreateBucketBody } from './schema.js';` line with the one above; `assertRole` stays imported.)

Replace the `GET '/admin/api/buckets'` handler body so it excludes the reserved bucket:
```ts
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getBucketStore();
		const all = ctx.roles.includes('super_admin')
			? await store.list()
			: await store.listByManager(ctx.userId);
		return all.filter((b) => b._id !== ADMIN_BUCKET_ID);
	})
```

Add these two routes to the chain (e.g. after the `POST '/admin/api/buckets'` route):
```ts
	.get('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return loadBucketForUsers(ctx, params.id);
	})
	.patch(
		'/admin/api/buckets/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForEdit(ctx, params.id);
			if (body.managedBy !== undefined) {
				assertRole(ctx, 'super_admin');
			}
			const updated = await getBucketStore().update(params.id, body);
			if (!updated) throw new AdminError(404, 'bucket not found');
			return updated;
		},
		{ body: UpdateBucketBody }
	)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `bun test test/admin/buckets_routes.spec.ts`
Expected: PASS (existing + 4 new tests).

- [ ] **Step 8: Commit**

```bash
git add lib/admin/auth/rbac.ts lib/admin/buckets/access.ts lib/admin/buckets/routes.ts lib/admin/buckets/schema.ts test/admin/buckets_routes.spec.ts
git commit -m "feat(admin): bucket detail GET/PATCH + project-backing access + reserved-bucket block"
```

---

### Task 5: End-user routes (`users-end`)

**Files:**
- Create: `lib/admin/users-end/schema.ts`
- Create: `lib/admin/users-end/routes.ts`
- Modify: `lib/admin/index.ts` (mount `endUserRoutes`)
- Test: create `test/admin/users_end_routes.spec.ts`

**Interfaces:**
- Consumes: `loadBucketForUsers` (Task 4); `getUserStore` from `lib/adapters/index.js`; `resolveAdmin`/`assertAuth`/`AdminError`/`AdminContext` from `rbac.js`.
- Produces: `endUserRoutes` (Elysia plugin) under `/admin/api/buckets/:id/users`.

- [ ] **Step 1: Write the schema.** Create `lib/admin/users-end/schema.ts`:
```ts
import { t } from 'elysia';

export const CreateEndUserBody = t.Object({
	email: t.String({ minLength: 3 }),
	password: t.String({ minLength: 8 }),
	roles: t.Optional(t.Array(t.String()))
});

export const UpdateEndUserBody = t.Object({
	roles: t.Optional(t.Array(t.String())),
	active: t.Optional(t.Boolean())
});

export const ResetPasswordBody = t.Object({
	password: t.String({ minLength: 8 })
});
```

- [ ] **Step 2: Write the failing test.** Create `test/admin/users_end_routes.spec.ts`:
```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getBucketStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes).use(endUserRoutes);
const client = treaty(app);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function makeBucket(roles: string[] = [], managedBy: string[] = []) {
	return getBucketStore().create({
		name: `b-${Math.random()}`,
		roles,
		managedBy
	});
}

describe('end-user API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access', async () => {
		const bucket = await makeBucket();
		const res = await client.admin.api.buckets({ id: bucket._id }).users.get();
		expect(res.status).toBe(401);
	});

	it('creates, lists (no password), edits, and deletes a user', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'u@x.io', password: 'supersecret', roles: ['viewer'] },
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
		const body = created.data as Record<string, unknown>;
		expect(body.password).toBeUndefined();
		const uid = body._id as string;

		const list = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie } });
		const users = list.data as Array<Record<string, unknown>>;
		expect(users.some((u) => u._id === uid)).toBe(true);
		expect(users.every((u) => u.password === undefined)).toBe(true);

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.patch({ active: false }, { headers: { cookie } });
		expect((patched.data as Record<string, unknown>).active).toBe(false);

		const del = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.delete(undefined, { headers: { cookie } });
		expect(del.status).toBe(200);
		expect(await getUserStore(bucket._id).find(uid)).toBeNull();
	});

	it('rejects roles not in the bucket set with 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'bad@x.io', password: 'supersecret', roles: ['admin'] },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(422);
	});

	it('rejects a duplicate email with 409', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const body = { email: 'dup@x.io', password: 'supersecret' };
		await client.admin.api.buckets({ id: bucket._id }).users.post(body, { headers: { cookie } });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(body, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('resets a password (stores a new hash)', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post({ email: 'pw@x.io', password: 'supersecret' }, { headers: { cookie } });
		const uid = (created.data as Record<string, unknown>)._id as string;
		const before = (await getUserStore(bucket._id).find(uid))?.password;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.password.post({ password: 'anothersecret' }, { headers: { cookie } });
		expect(res.status).toBe(200);
		const after = (await getUserStore(bucket._id).find(uid))?.password;
		expect(after).not.toBe(before);
	});

	it('lets a project_admin manage users of a bucket backing their project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket(); // not owned by pa
		const proj = await getProjectStore().create({
			name: 'PM',
			slug: `pm-${Math.random()}`,
			managedBy: [pa.userId]
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post({ email: 'via@x.io', password: 'supersecret' }, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(201);
	});

	it('denies a project_admin a bucket they neither own nor reach via a project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket();
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('refuses to manage users of the reserved admin bucket', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.users.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/users_end_routes.spec.ts`
Expected: FAIL (`lib/admin/users-end/routes.ts` does not exist).

- [ ] **Step 4: Implement the routes.** Create `lib/admin/users-end/routes.ts`:
```ts
import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	assertAuth,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForUsers } from '../buckets/access.js';
import {
	CreateEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody
} from './schema.js';

function assertRolesSubset(
	roles: string[] | undefined,
	bucket: UserBucket
): void {
	if (!roles) return;
	const bad = roles.filter((r) => !bucket.roles.includes(r));
	if (bad.length) {
		throw new AdminError(422, `roles not declared on bucket: ${bad.join(', ')}`);
	}
}

const strip = (u: { password?: string }) => {
	const { password: _password, ...safe } = u;
	return safe;
};

export const endUserRoutes = new Elysia({ name: 'admin-users-end' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/buckets/:id/users', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadBucketForUsers(ctx, params.id);
		const users = await getUserStore(params.id).list();
		return users.map(strip);
	})
	.post(
		'/admin/api/buckets/:id/users',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			assertRolesSubset(body.roles, bucket);
			const store = getUserStore(params.id);
			if (await store.findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			const user = await store.create(body.email, hash, body.roles ?? []);
			set.status = 201;
			return strip(user);
		},
		{ body: CreateEndUserBody }
	)
	.patch(
		'/admin/api/buckets/:id/users/:uid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			assertRolesSubset(body.roles, bucket);
			const updated = await getUserStore(params.id).update(params.uid, body);
			if (!updated) throw new AdminError(404, 'user not found');
			return strip(updated);
		},
		{ body: UpdateEndUserBody }
	)
	.post(
		'/admin/api/buckets/:id/users/:uid/password',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadBucketForUsers(ctx, params.id);
			const hash = await Bun.password.hash(body.password);
			const updated = await getUserStore(params.id).update(params.uid, {
				password: hash
			});
			if (!updated) throw new AdminError(404, 'user not found');
			return { ok: true };
		},
		{ body: ResetPasswordBody }
	)
	.delete('/admin/api/buckets/:id/users/:uid', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadBucketForUsers(ctx, params.id);
		const store = getUserStore(params.id);
		if (!(await store.find(params.uid))) {
			throw new AdminError(404, 'user not found');
		}
		await store.destroy(params.uid);
		return { ok: true };
	});
```

- [ ] **Step 5: Mount into adminApp.** In `lib/admin/index.ts`:

Add the import near the other route imports:
```ts
import { endUserRoutes } from './users-end/routes.js';
```
Add to the chain after `.use(bucketRoutes)`:
```ts
	.use(endUserRoutes)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `bun test test/admin/users_end_routes.spec.ts`
Expected: PASS (8 tests).

- [ ] **Step 7: Commit**

```bash
git add lib/admin/users-end/schema.ts lib/admin/users-end/routes.ts lib/admin/index.ts test/admin/users_end_routes.spec.ts
git commit -m "feat(admin): per-bucket end-user CRUD routes"
```

---

### Task 6: UI — Buckets section + BucketDetail + Projects "Users" shortcut

**Files:**
- Create: `lib/admin/ui/pages/Buckets.tsx`
- Create: `lib/admin/ui/pages/BucketDetail.tsx`
- Modify: `lib/admin/ui/pages/Layout.tsx` (Buckets nav item; pass `isSuperAdmin` to Projects/Buckets)
- Modify: `lib/admin/ui/pages/Projects.tsx` (accept `isSuperAdmin`; add "Users" row action)
- Build: `bun build.ts`

**Interfaces:**
- Consumes: the Task 4/5 endpoints.
- Produces:
  - `BucketDetail({ bucketId, onBack, isSuperAdmin }: { bucketId: string; onBack: () => void; isSuperAdmin: boolean })`.
  - `Buckets({ isSuperAdmin }: { isSuperAdmin: boolean })`.
  - `Projects({ isSuperAdmin }: { isSuperAdmin: boolean })` (signature change).

- [ ] **Step 1: Implement BucketDetail.** Create `lib/admin/ui/pages/BucketDetail.tsx`:
```tsx
import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Switch,
	Space,
	Tag,
	Typography,
	Popconfirm,
	message
} from 'antd';
import { ArrowLeftOutlined, PlusOutlined } from '@ant-design/icons';
import type { UserBucket, User } from '../../../adapters/types.js';

type EndUser = Omit<User, 'password'>;

interface CreateValues {
	email: string;
	password: string;
	roles?: string[];
}

export function BucketDetail({
	bucketId,
	onBack,
	isSuperAdmin
}: {
	bucketId: string;
	onBack: () => void;
	isSuperAdmin: boolean;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const [bucket, setBucket] = useState<UserBucket | null>(null);
	const [rows, setRows] = useState<EndUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [editOpen, setEditOpen] = useState(false);
	const [pwUser, setPwUser] = useState<EndUser | null>(null);
	const [bucketEditOpen, setBucketEditOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [createForm] = Form.useForm<CreateValues>();
	const [editForm] = Form.useForm<{ roles?: string[]; active: boolean }>();
	const [pwForm] = Form.useForm<{ password: string }>();
	const [bucketForm] = Form.useForm<{ name: string; roles?: string[] }>();

	const roleOptions = (bucket?.roles ?? []).map((r) => ({ label: r, value: r }));

	async function load() {
		setLoading(true);
		try {
			const [b, u] = await Promise.all([fetch(base), fetch(`${base}/users`)]);
			if (b.ok) setBucket((await b.json()) as UserBucket);
			if (u.ok) setRows((await u.json()) as EndUser[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [bucketId]);

	async function post(path: string, bodyObj: unknown, okMsg: string) {
		const res = await fetch(`${base}${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(bodyObj)
		});
		const body = (await res.json().catch(() => null)) as { message?: string } | null;
		if (!res.ok) {
			message.error(body?.message || `failed: ${okMsg}`);
			return false;
		}
		return true;
	}

	async function onCreate(values: CreateValues) {
		setSaving(true);
		try {
			if (await post('/users', values, 'create user')) {
				setCreateOpen(false);
				createForm.resetFields();
				await load();
			}
		} finally {
			setSaving(false);
		}
	}

	async function onEdit(values: { roles?: string[]; active: boolean }) {
		if (!editUserId) return;
		const res = await fetch(`${base}/users/${editUserId}`, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			message.error('failed to update user');
			return;
		}
		setEditOpen(false);
		await load();
	}

	const [editUserId, setEditUserId] = useState<string | null>(null);

	async function onResetPassword(values: { password: string }) {
		if (!pwUser) return;
		if (await post(`/users/${pwUser._id}/password`, values, 'reset password')) {
			message.success('password reset');
			setPwUser(null);
			pwForm.resetFields();
		}
	}

	async function onDelete(uid: string) {
		const res = await fetch(`${base}/users/${uid}`, { method: 'DELETE' });
		if (!res.ok) {
			message.error('failed to delete user');
			return;
		}
		await load();
	}

	async function onSaveBucket(values: { name: string; roles?: string[] }) {
		const res = await fetch(base, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			message.error('failed to update bucket');
			return;
		}
		setBucketEditOpen(false);
		await load();
	}

	return (
		<>
			<Space style={{ marginBottom: 16, justifyContent: 'space-between', width: '100%' }}>
				<Button icon={<ArrowLeftOutlined />} onClick={onBack}>
					Back
				</Button>
				<Typography.Title level={4} style={{ margin: 0 }}>
					{bucket?.name ?? bucketId} — users
				</Typography.Title>
				<Space>
					<Button
						onClick={() => {
							bucketForm.setFieldsValue({
								name: bucket?.name ?? '',
								roles: bucket?.roles ?? []
							});
							setBucketEditOpen(true);
						}}
					>
						Edit bucket
					</Button>
					<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
						New user
					</Button>
				</Space>
			</Space>
			<div style={{ marginBottom: 12 }}>
				{(bucket?.roles ?? []).map((r) => (
					<Tag key={r}>{r}</Tag>
				))}
			</div>
			<Table<EndUser>
				rowKey="_id"
				loading={loading}
				dataSource={rows}
				columns={[
					{ title: 'Email', dataIndex: 'email' },
					{
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) => roles.map((r) => <Tag key={r}>{r}</Tag>)
					},
					{
						title: 'Active',
						dataIndex: 'active',
						render: (a: boolean) => (a ? <Tag color="green">active</Tag> : <Tag>inactive</Tag>)
					},
					{
						title: 'Verified',
						dataIndex: 'verified',
						render: (v: boolean) => (v ? 'yes' : 'no')
					},
					{
						title: 'Actions',
						render: (_: unknown, row: EndUser) => (
							<Space>
								<Button
									size="small"
									onClick={() => {
										setEditUserId(row._id);
										editForm.setFieldsValue({ roles: row.roles, active: row.active });
										setEditOpen(true);
									}}
								>
									Edit
								</Button>
								<Button size="small" onClick={() => setPwUser(row)}>
									Reset password
								</Button>
								<Popconfirm title="Delete this user?" onConfirm={() => onDelete(row._id)}>
									<Button size="small" danger>
										Delete
									</Button>
								</Popconfirm>
							</Space>
						)
					}
				]}
			/>

			<Modal
				title="New user"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => createForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<CreateValues> form={createForm} layout="vertical" onFinish={onCreate}>
					<Form.Item name="email" label="Email" rules={[{ required: true, type: 'email' }]}>
						<Input />
					</Form.Item>
					<Form.Item name="password" label="Initial password" rules={[{ required: true, min: 8 }]}>
						<Input.Password placeholder="at least 8 characters" />
					</Form.Item>
					<Form.Item name="roles" label="Roles">
						<Select mode="multiple" options={roleOptions} />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Edit user"
				open={editOpen}
				onCancel={() => setEditOpen(false)}
				onOk={() => editForm.submit()}
				destroyOnHidden
			>
				<Form form={editForm} layout="vertical" onFinish={onEdit}>
					<Form.Item name="roles" label="Roles">
						<Select mode="multiple" options={roleOptions} />
					</Form.Item>
					<Form.Item name="active" label="Active" valuePropName="checked">
						<Switch />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Reset password"
				open={pwUser !== null}
				onCancel={() => setPwUser(null)}
				onOk={() => pwForm.submit()}
				destroyOnHidden
			>
				<Form form={pwForm} layout="vertical" onFinish={onResetPassword}>
					<Form.Item name="password" label="New password" rules={[{ required: true, min: 8 }]}>
						<Input.Password />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Edit bucket"
				open={bucketEditOpen}
				onCancel={() => setBucketEditOpen(false)}
				onOk={() => bucketForm.submit()}
				destroyOnHidden
			>
				<Form form={bucketForm} layout="vertical" onFinish={onSaveBucket}>
					<Form.Item name="name" label="Name" rules={[{ required: true }]}>
						<Input />
					</Form.Item>
					<Form.Item name="roles" label="Roles" tooltip="Role set users in this bucket may hold">
						<Select mode="tags" placeholder="add role names" />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
```

- [ ] **Step 2: Implement Buckets list.** Create `lib/admin/ui/pages/Buckets.tsx`:
```tsx
import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket, Project } from '../../../adapters/types.js';
import { BucketDetail } from './BucketDetail.js';

interface CreateBucketValues {
	name: string;
	roles?: string[];
}

export function Buckets({ isSuperAdmin }: { isSuperAdmin: boolean }) {
	const [buckets, setBuckets] = useState<UserBucket[]>([]);
	const [projects, setProjects] = useState<Project[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateBucketValues>();
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);

	async function load() {
		setLoading(true);
		try {
			const [b, p] = await Promise.all([
				fetch('/admin/api/buckets'),
				fetch('/admin/api/projects')
			]);
			if (b.ok) setBuckets((await b.json()) as UserBucket[]);
			if (p.ok) setProjects((await p.json()) as Project[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function onCreate(values: CreateBucketValues) {
		setCreating(true);
		try {
			const res = await fetch('/admin/api/buckets', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as { message?: string } | null;
				message.error(body?.message || 'failed to create bucket');
				return;
			}
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	function projectCount(bucketId: string): number {
		return projects.filter((p) => p.bucketId === bucketId).length;
	}

	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => {
					setOpenBucketId(null);
					load();
				}}
				isSuperAdmin={isSuperAdmin}
			/>
		);
	}

	return (
		<>
			{isSuperAdmin && (
				<div style={{ marginBottom: 16, textAlign: 'right' }}>
					<Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
						New bucket
					</Button>
				</div>
			)}
			<Table<UserBucket>
				rowKey="_id"
				loading={loading}
				dataSource={buckets}
				columns={[
					{ title: 'Name', dataIndex: 'name' },
					{
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) => roles.map((r) => <Tag key={r}>{r}</Tag>)
					},
					{
						title: 'Projects',
						render: (_: unknown, row: UserBucket) => projectCount(row._id)
					},
					{
						title: '',
						render: (_: unknown, row: UserBucket) => (
							<Button size="small" onClick={() => setOpenBucketId(row._id)}>
								Users
							</Button>
						)
					}
				]}
			/>
			<Modal
				title="New bucket"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateBucketValues> form={form} layout="vertical" onFinish={onCreate}>
					<Form.Item name="name" label="Name" rules={[{ required: true }]}>
						<Input />
					</Form.Item>
					<Form.Item name="roles" label="Roles">
						<Select mode="tags" placeholder="add role names" />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
```

- [ ] **Step 3: Wire Buckets into the Layout nav.** In `lib/admin/ui/pages/Layout.tsx`:

Add the import:
```tsx
import { Buckets } from './Buckets.js';
```
Add `DatabaseOutlined` to the `@ant-design/icons` import.
Extend the `PageKey` type:
```tsx
type PageKey = 'projects' | 'buckets' | 'admins' | 'settings' | 'keys';
```
Add a Buckets nav item after Projects (visible to everyone):
```tsx
		{ key: 'projects', icon: <ProjectOutlined />, label: 'Projects' },
		{ key: 'buckets', icon: <DatabaseOutlined />, label: 'Buckets' },
```
Update `renderPage()` to pass `isSuperAdmin` and handle `buckets`:
```tsx
	function renderPage() {
		switch (selected) {
			case 'buckets':
				return <Buckets isSuperAdmin={isSuperAdmin} />;
			case 'admins':
				return isSuperAdmin ? <Admins /> : <Projects isSuperAdmin={isSuperAdmin} />;
			case 'settings':
				return <Stub title="Settings" />;
			case 'keys':
				return <Stub title="Keys" />;
			default:
				return <Projects isSuperAdmin={isSuperAdmin} />;
		}
	}
```

- [ ] **Step 4: Add the Projects "Users" shortcut.** In `lib/admin/ui/pages/Projects.tsx`:

Add the import:
```tsx
import { BucketDetail } from './BucketDetail.js';
```
Change the component signature:
```tsx
export function Projects({ isSuperAdmin }: { isSuperAdmin: boolean }) {
```
Add state after the existing `useState` calls:
```tsx
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);
```
Add a short-circuit before the `if (openProject)` block:
```tsx
	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => setOpenBucketId(null)}
				isSuperAdmin={isSuperAdmin}
			/>
		);
	}
```
Replace the trailing action column (the one that renders the "Clients" button) so it renders both actions, with "Users" disabled when the project has no bucket:
```tsx
					{
						title: '',
						render: (_: unknown, row: Project) => (
							<Space>
								<Button size="small" onClick={() => setOpenProject(row)}>
									Clients
								</Button>
								<Button
									size="small"
									disabled={!row.bucketId}
									onClick={() => row.bucketId && setOpenBucketId(row.bucketId)}
								>
									Users
								</Button>
							</Space>
						)
					}
```
Add `Space` to the existing antd import line.

- [ ] **Step 5: Build the bundle**

Run: `bun build.ts`
Expected: `built ./lib/admin/ui/adminClient.tsx → public/admin.js` with no errors.

- [ ] **Step 6: Typecheck the new/changed UI**

Run: `bun run typecheck 2>&1 | grep -E "Buckets.tsx|BucketDetail.tsx|Projects.tsx|Layout.tsx" || echo "clean"`
Expected: `clean`.

- [ ] **Step 7: Commit**

```bash
git add lib/admin/ui/pages/Buckets.tsx lib/admin/ui/pages/BucketDetail.tsx lib/admin/ui/pages/Layout.tsx lib/admin/ui/pages/Projects.tsx public/admin.js
git commit -m "feat(admin): buckets section + end-user management UI"
```
(`public/admin.js` is a build artifact; include it only if the repo tracks built bundles — otherwise drop it from the `git add`.)

---

### Task 7: Full verification + browser e2e

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `bun test`
Expected: all pass, 0 fail (SP-1/SP-2 counts + new store/resolve_bucket/seed/buckets_routes/users_end tests). If a lone cross-suite flake appears (see the admin memory-store notes), re-run the failing file in isolation before treating it as a real failure.

- [ ] **Step 2: Typecheck**

Run: `bun run typecheck 2>&1 | grep -E "users-end|BucketDetail|Buckets.tsx|resolveBucket|access.ts" || echo "no new type errors in SP-3 files"`
Expected: `no new type errors in SP-3 files`.

- [ ] **Step 3: Browser e2e (real flow).** Start the server (`bun lib/index.ts`), log in to `/admin` as super_admin. Then:
  - Open **Buckets** → confirm the admin bucket is NOT listed, and `Default users` (redfox) is. Create a new bucket with roles `viewer, editor`.
  - Open that bucket → **New user** (email + password + role `viewer`) → confirm it appears with password never shown; **Edit** to toggle active/roles; **Reset password**; **Delete**.
  - From **Projects**, set a regular project's bucket (if needed) and use the **Users** shortcut → confirm it lands on the same bucket detail; confirm the button is disabled for a project with no bucket.
  - Confirm the console is free of hydration/errors. Kill all `bun` processes afterward (`Get-Process bun | Stop-Process -Force`).

- [ ] **Step 4: Verify login routing end-to-end.** Create a client in a regular project (SP-2 Clients UI) whose project has a custom bucket with a seeded user; run an `/auth` → `/ui/:uid/login` for that client and confirm the user in the project's bucket authenticates (303) while a redfox-only user is rejected (400) — proving assigned clients route to their bucket. Confirm an unassigned client still authenticates a redfox user (303).

- [ ] **Step 5: Final commit (if any verification fixes were needed)**

```bash
git add -A
git commit -m "test(admin): verify SP-3 user & bucket management end-to-end"
```

---

## Self-Review

**Spec coverage:**
- `UserStore.destroy` + `ProjectStore.findByClientId` → Task 1. ✓
- `resolveBucketForClient` + login routing (admin/assigned/redfox fallback) → Task 2. ✓
- Seed manageable `redfox` bucket → Task 3. ✓
- Bucket GET/PATCH, two access levels (`assertBucketAccess` strict for edit, `assertBucketUserAccess` broad for read/users), reserved-bucket block, list exclusion → Task 4. ✓
- End-user CRUD (list/create/edit/reset-password/deactivate/delete), role-subset 422, dup-email 409, password stripping, project-backing access → Task 5. ✓
- Buckets UI section + BucketDetail + Projects "Users" shortcut + Layout nav → Task 6. ✓
- Testing (store, routing, seed, bucket routes, user routes, regression, e2e) → Tasks 1–7. ✓
- Deferred (rich auth-methods, import/export) → not built; `authMethods` left non-editable. ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code. ✓

**Type consistency:** `resolveBucketForClient`, `assertBucketUserAccess`, `loadBucketForUsers`/`loadBucketForEdit`, `endUserRoutes`, `BucketDetail`/`Buckets`/`Projects` signatures match between defining tasks (2, 4, 5, 6) and their consumers. `UserBucket`/`User`/`Project` types used consistently. Deactivate is `PATCH { active: false }`; delete is `DELETE` (hard). ✓

**Note for implementer:** end-user records live in per-bucket `user_<bucketId>` collections; always reach them via `getUserStore(bucketId)`. The reserved admin bucket (`ADMIN_BUCKET_ID`) is blocked in `loadBucketForUsers`/`loadBucketForEdit`, so it is impossible to reach `user_admin` through SP-3 routes — admin accounts stay on `/admin/api/admins`.
