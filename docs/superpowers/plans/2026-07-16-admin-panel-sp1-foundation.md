# Admin Panel SP-1 (Admin Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the admin-panel foundation — project/bucket/admin-user data model, OIDC-based (BFF) admin login, RBAC, project/admin/bucket CRUD APIs, and a React app shell — mounted under `/admin/*` on the existing server.

**Architecture:** New stores (`projects`, `userBuckets`, `adminSession`) sit behind the repo's adapter interfaces with MongoDB + in-memory implementations. The admin panel is a first-party OAuth client of this server; a BFF session (server-side tokens, one httpOnly cookie) is established after the normal OIDC flow. RBAC middleware resolves the admin from the session cookie and gates project/bucket routes. Users live in per-bucket collections (`user_<bucketId>`), reusing the existing `user_<name>` scheme.

**Tech Stack:** Bun (runtime, test runner, bundler), Elysia 1.4 (HTTP), TypeScript 6 (strict), MongoDB 7, React 19 + Ant Design 6, TypeBox (`elysia`'s `t`), Bun's test runner + Chai + Sinon + Eden treaty client.

## Global Constraints

- **Indentation:** tabs. **Quotes:** single. **Trailing commas:** none. (Prettier enforces; `bun run format` must pass before every commit.)
- **No `any`** — use proper types or `unknown` with narrowing (ESLint enforces).
- **Unused vars** must be prefixed `_`.
- **No comments explaining _what_** — only _why_, when non-obvious.
- **Imports** use `.js`/`.ts` extensions and the `lib/` + `test/` path aliases, matching existing files.
- **Tests:** Bun's native runner (`import { describe, it, expect, beforeAll } from 'bun:test'`), Chai `expect` where the repo uses it, Eden `treaty` for HTTP. Route/integration specs bootstrap via `bootstrap(import.meta)`.
- **Errors on protocol endpoints** throw `OIDCProviderError` subclasses; **admin routes do NOT** — they return plain JSON `{ error, message }` with an explicit status.
- **Reserved identifiers** (define once in `lib/admin/consts.ts`, import everywhere): `ADMIN_PROJECT_ID = 'admin'`, `ADMIN_BUCKET_ID = 'admin'`, `ADMIN_CLIENT_ID = 'admin-panel'`, `ADMIN_SESSION_COOKIE = '_admin_session'`.

---

## File Structure

**New files**

- `lib/admin/consts.ts` — reserved ids/constants.
- `lib/admin/auth/session.ts` — BFF session helpers (create/verify/destroy).
- `lib/admin/auth/rbac.ts` — `resolveAdmin` derive + `requireRole` / `requireProjectAccess` / `requireBucketAccess`.
- `lib/admin/auth/login.ts` — `/admin/login`, `/admin/callback`, `/admin/api/logout`, `/admin/api/me`.
- `lib/admin/auth/setup.ts` — first-run super-admin creation (hard-gated).
- `lib/admin/projects/routes.ts`, `lib/admin/projects/schema.ts`.
- `lib/admin/users/routes.ts`, `lib/admin/users/schema.ts` — admin-account CRUD.
- `lib/admin/buckets/routes.ts`, `lib/admin/buckets/schema.ts`.
- `lib/admin/index.ts` — Elysia plugin aggregating admin routes + JSON error scope.
- `lib/admin/ui/adminClient.tsx`, `lib/admin/ui/serverRender.tsx`, `lib/admin/ui/pages/*` — SPA.
- `lib/adapters/memory/projectStore.ts`, `userBucketStore.ts`, `adminSessionStore.ts`.
- `lib/adapters/mongodb/projectStore.ts`, `userBucketStore.ts`, `adminSessionStore.ts`.
- `test/admin/*.spec.ts`, `test/admin/admin.config.ts`.

**Modified files**

- `lib/adapters/types.ts` — add store interfaces + `User.roles`.
- `lib/adapters/index.ts` — wire `getProjectStore` / `getBucketStore` / `adminSessionStore`.
- `lib/adapters/memory/index.ts`, `lib/adapters/mongodb/index.ts` — export new stores.
- `lib/adapters/memory/userStore.ts`, `lib/adapters/mongodb/userStore.ts` — `roles`, `list`, `update`, `create` returns `User`.
- `database/collections.ts` — add `'projects'`, `'userBuckets'`, `'adminSession'`.
- `database/mongodb.ts` — seed admin project + Administrators bucket + panel client.
- `lib/index.ts` — mount the admin plugin.
- `lib/interactions/index.ts` — special-case: admin-panel client authenticates against the admin bucket.
- `package.json` — add `admin` bundle to `build`/`watch` scripts.

---

## Task 1: Project store

**Files:**

- Modify: `lib/adapters/types.ts`
- Create: `lib/adapters/memory/projectStore.ts`
- Modify: `lib/adapters/memory/index.ts`
- Create: `lib/adapters/mongodb/projectStore.ts`
- Modify: `lib/adapters/mongodb/index.ts`
- Modify: `lib/adapters/index.ts`
- Test: `test/admin/project_store.spec.ts`

**Interfaces:**

- Produces: `Project` type; `ProjectStoreInstance`; `getProjectStore(): ProjectStoreInstance`.

- [ ] **Step 1: Add types to `lib/adapters/types.ts`**

Append:

```ts
export interface Project {
	_id: string;
	name: string;
	slug: string;
	type: 'admin' | 'regular';
	managedBy: string[];
	bucketId: string | null;
	createdAt: Date;
	updatedAt: Date;
}

export interface ProjectStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
	}): Promise<Project>;
	find(id: string): Promise<Project | null>;
	findBySlug(slug: string): Promise<Project | null>;
	list(): Promise<Project[]>;
	listByManager(userId: string): Promise<Project[]>;
	update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId'>>
	): Promise<Project | null>;
	destroy(id: string): Promise<void>;
	countByBucket(bucketId: string): Promise<number>;
}

export interface ProjectStoreConstructor {
	new (): ProjectStoreInstance;
}
```

- [ ] **Step 2: Write the failing test `test/admin/project_store.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { ProjectStore } from 'lib/adapters/memory/projectStore.ts';

describe('ProjectStore (memory)', () => {
	let store: ProjectStore;
	beforeEach(() => {
		store = new ProjectStore();
	});

	it('creates and finds a project', async () => {
		const p = await store.create({ name: 'Acme', slug: 'acme' });
		expect(p._id).toBeString();
		expect(p.type).toBe('regular');
		expect(await store.find(p._id)).toMatchObject({ slug: 'acme' });
	});

	it('finds by slug and lists by manager', async () => {
		await store.create({ name: 'Acme', slug: 'acme', managedBy: ['u1'] });
		await store.create({ name: 'Globex', slug: 'globex', managedBy: ['u2'] });
		expect(await store.findBySlug('globex')).toMatchObject({ name: 'Globex' });
		const mine = await store.listByManager('u1');
		expect(mine).toHaveLength(1);
		expect(mine[0].slug).toBe('acme');
	});

	it('updates, counts by bucket, and destroys', async () => {
		const p = await store.create({ name: 'Acme', slug: 'acme' });
		await store.update(p._id, { bucketId: 'b1' });
		expect(await store.countByBucket('b1')).toBe(1);
		await store.destroy(p._id);
		expect(await store.find(p._id)).toBeNull();
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/project_store.spec.ts`
Expected: FAIL — cannot find module `lib/adapters/memory/projectStore.ts`.

- [ ] **Step 4: Implement `lib/adapters/memory/projectStore.ts`**

```ts
import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class ProjectStore implements ProjectStoreInstance {
	private projects = new Map<string, Project>();

	async create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
	}): Promise<Project> {
		const now = new Date();
		const project: Project = {
			_id: data._id ?? nanoid(),
			name: data.name,
			slug: data.slug,
			type: data.type ?? 'regular',
			managedBy: data.managedBy ?? [],
			bucketId: data.bucketId ?? null,
			createdAt: now,
			updatedAt: now
		};
		this.projects.set(project._id, project);
		return project;
	}

	async find(id: string): Promise<Project | null> {
		return this.projects.get(id) ?? null;
	}

	async findBySlug(slug: string): Promise<Project | null> {
		for (const p of this.projects.values()) {
			if (p.slug === slug) return p;
		}
		return null;
	}

	async list(): Promise<Project[]> {
		return [...this.projects.values()];
	}

	async listByManager(userId: string): Promise<Project[]> {
		return [...this.projects.values()].filter((p) =>
			p.managedBy.includes(userId)
		);
	}

	async update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId'>>
	): Promise<Project | null> {
		const p = this.projects.get(id);
		if (!p) return null;
		Object.assign(p, patch, { updatedAt: new Date() });
		return p;
	}

	async destroy(id: string): Promise<void> {
		this.projects.delete(id);
	}

	async countByBucket(bucketId: string): Promise<number> {
		return [...this.projects.values()].filter((p) => p.bucketId === bucketId)
			.length;
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/project_store.spec.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Implement the MongoDB store `lib/adapters/mongodb/projectStore.ts`**

```ts
import { db } from './db.js';
import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class ProjectStore implements ProjectStoreInstance {
	private collection = db.collection<Project>('projects');

	async create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
	}): Promise<Project> {
		const now = new Date();
		const project: Project = {
			_id: data._id ?? nanoid(),
			name: data.name,
			slug: data.slug,
			type: data.type ?? 'regular',
			managedBy: data.managedBy ?? [],
			bucketId: data.bucketId ?? null,
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(project);
		return project;
	}

	async find(id: string): Promise<Project | null> {
		return this.collection.findOne({ _id: id });
	}

	async findBySlug(slug: string): Promise<Project | null> {
		return this.collection.findOne({ slug });
	}

	async list(): Promise<Project[]> {
		return this.collection.find().toArray();
	}

	async listByManager(userId: string): Promise<Project[]> {
		return this.collection.find({ managedBy: userId }).toArray();
	}

	async update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId'>>
	): Promise<Project | null> {
		return this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async countByBucket(bucketId: string): Promise<number> {
		return this.collection.countDocuments({ bucketId });
	}
}
```

- [ ] **Step 7: Export from adapter index files**

In `lib/adapters/memory/index.ts` add:

```ts
export { ProjectStore } from './projectStore.js';
```

In `lib/adapters/mongodb/index.ts` add:

```ts
export { ProjectStore } from './projectStore.js';
```

- [ ] **Step 8: Wire `getProjectStore` in `lib/adapters/index.ts`**

Add to the imports from `./memory/index.js`: `ProjectStore as MemoryProjectStore`. Add the type import `ProjectStoreConstructor, ProjectStoreInstance`. After the existing `if (process.env.MONGODB_URI)` block, add `ProjectStoreClass` selection and a singleton accessor:

```ts
let ProjectStoreClass: ProjectStoreConstructor = MemoryProjectStore;
// inside the existing `if (process.env.MONGODB_URI)` block:
ProjectStoreClass = mongodb.ProjectStore;

let projectStoreSingleton: ProjectStoreInstance | null = null;
export function getProjectStore(): ProjectStoreInstance {
	if (!projectStoreSingleton) {
		projectStoreSingleton = new ProjectStoreClass();
	}
	return projectStoreSingleton;
}
```

- [ ] **Step 9: Run the full admin test file + format**

Run: `bun test test/admin/project_store.spec.ts && bun run format`
Expected: PASS; no lint/format errors.

- [ ] **Step 10: Commit**

```bash
git add lib/adapters test/admin/project_store.spec.ts
git commit -m "feat(admin): project store (memory + mongodb adapters)"
```

---

## Task 2: User-bucket store

**Files:**

- Modify: `lib/adapters/types.ts`
- Create: `lib/adapters/memory/userBucketStore.ts`, `lib/adapters/mongodb/userBucketStore.ts`
- Modify: `lib/adapters/memory/index.ts`, `lib/adapters/mongodb/index.ts`, `lib/adapters/index.ts`
- Test: `test/admin/bucket_store.spec.ts`

**Interfaces:**

- Produces: `UserBucket` type; `UserBucketStoreInstance`; `getBucketStore(): UserBucketStoreInstance`.

- [ ] **Step 1: Add types to `lib/adapters/types.ts`**

```ts
export interface UserBucket {
	_id: string;
	name: string;
	managedBy: string[];
	roles: string[];
	authMethods: string[];
	createdAt: Date;
	updatedAt: Date;
}

export interface UserBucketStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
	}): Promise<UserBucket>;
	find(id: string): Promise<UserBucket | null>;
	list(): Promise<UserBucket[]>;
	listByManager(userId: string): Promise<UserBucket[]>;
	update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
		>
	): Promise<UserBucket | null>;
	destroy(id: string): Promise<void>;
}

export interface UserBucketStoreConstructor {
	new (): UserBucketStoreInstance;
}
```

- [ ] **Step 2: Write the failing test `test/admin/bucket_store.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

describe('UserBucketStore (memory)', () => {
	let store: UserBucketStore;
	beforeEach(() => {
		store = new UserBucketStore();
	});

	it('creates with default authMethods and finds', async () => {
		const b = await store.create({ name: 'Dev users', managedBy: ['u1'] });
		expect(b.authMethods).toEqual(['password']);
		expect(await store.find(b._id)).toMatchObject({ name: 'Dev users' });
	});

	it('lists by manager and updates roles', async () => {
		const b = await store.create({ name: 'Dev', managedBy: ['u1'] });
		expect(await store.listByManager('u1')).toHaveLength(1);
		await store.update(b._id, { roles: ['viewer', 'editor'] });
		expect((await store.find(b._id))?.roles).toEqual(['viewer', 'editor']);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/bucket_store.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `lib/adapters/memory/userBucketStore.ts`**

```ts
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private buckets = new Map<string, UserBucket>();

	async create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			managedBy: data.managedBy ?? [],
			roles: data.roles ?? [],
			authMethods: data.authMethods ?? ['password'],
			createdAt: now,
			updatedAt: now
		};
		this.buckets.set(bucket._id, bucket);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return this.buckets.get(id) ?? null;
	}

	async list(): Promise<UserBucket[]> {
		return [...this.buckets.values()];
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return [...this.buckets.values()].filter((b) =>
			b.managedBy.includes(userId)
		);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
		>
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b) return null;
		Object.assign(b, patch, { updatedAt: new Date() });
		return b;
	}

	async destroy(id: string): Promise<void> {
		this.buckets.delete(id);
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/bucket_store.spec.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Implement `lib/adapters/mongodb/userBucketStore.ts`**

```ts
import { db } from './db.js';
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private collection = db.collection<UserBucket>('userBuckets');

	async create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			managedBy: data.managedBy ?? [],
			roles: data.roles ?? [],
			authMethods: data.authMethods ?? ['password'],
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(bucket);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return this.collection.findOne({ _id: id });
	}

	async list(): Promise<UserBucket[]> {
		return this.collection.find().toArray();
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return this.collection.find({ managedBy: userId }).toArray();
	}

	async update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
		>
	): Promise<UserBucket | null> {
		return this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
```

- [ ] **Step 7: Export + wire**

Add `export { UserBucketStore } from './userBucketStore.js';` to both `lib/adapters/memory/index.ts` and `lib/adapters/mongodb/index.ts`. In `lib/adapters/index.ts` mirror Task 1 Step 8 with `MemoryUserBucketStore`, `BucketStoreClass`, and:

```ts
let bucketStoreSingleton: UserBucketStoreInstance | null = null;
export function getBucketStore(): UserBucketStoreInstance {
	if (!bucketStoreSingleton) {
		bucketStoreSingleton = new BucketStoreClass();
	}
	return bucketStoreSingleton;
}
```

- [ ] **Step 8: Run + format + commit**

```bash
bun test test/admin/bucket_store.spec.ts && bun run format
git add lib/adapters test/admin/bucket_store.spec.ts
git commit -m "feat(admin): user-bucket store (memory + mongodb adapters)"
```

---

## Task 3: User roles + store extensions

**Files:**

- Modify: `lib/adapters/types.ts`, `lib/adapters/memory/userStore.ts`, `lib/adapters/mongodb/userStore.ts`, `lib/interactions/index.ts`
- Test: `test/admin/user_store.spec.ts`

**Interfaces:**

- Consumes: existing `UserStoreInstance`.
- Produces: `User.roles: string[]`; `create(email, password, roles?) => Promise<User>`; `list() => Promise<User[]>`; `update(id, patch) => Promise<User | null>`.

- [ ] **Step 1: Extend `User` and `UserStoreInstance` in `lib/adapters/types.ts`**

Add `roles: string[];` to the `User` interface. Replace the `UserStoreInstance` methods block with:

```ts
export interface UserStoreInstance {
	find(id: string): Promise<User | null>;
	findByEmail(email: string): Promise<User | null>;
	create(email: string, password: string, roles?: string[]): Promise<User>;
	list(): Promise<User[]>;
	update(
		id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password'>>
	): Promise<User | null>;
}
```

- [ ] **Step 2: Write the failing test `test/admin/user_store.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { UserStore } from 'lib/adapters/memory/userStore.ts';

describe('UserStore (memory) roles', () => {
	let store: UserStore;
	beforeEach(() => {
		store = new UserStore('admin');
	});

	it('creates a user with roles and returns it', async () => {
		const u = await store.create('a@x.io', 'hash', ['super_admin']);
		expect(u.roles).toEqual(['super_admin']);
		expect(u._id).toBeString();
	});

	it('lists users and updates roles', async () => {
		await store.create('a@x.io', 'hash', ['super_admin']);
		const u = await store.create('b@x.io', 'hash');
		expect(await store.list()).toHaveLength(2);
		await store.update(u._id, { roles: ['project_admin'] });
		expect((await store.find(u._id))?.roles).toEqual(['project_admin']);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/user_store.spec.ts`
Expected: FAIL — `create` returns `void`/no `roles`, `list`/`update` undefined.

- [ ] **Step 4: Update `lib/adapters/memory/userStore.ts`**

Replace `create` and add `list`/`update`; include `roles`:

```ts
import { type User, type UserStoreInstance } from '../types.js';

export class UserStore implements UserStoreInstance {
	private users = new Map<string, User>();
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	async find(_id: string): Promise<User | null> {
		return this.users.get(_id) || null;
	}

	async findByEmail(email: string): Promise<User | null> {
		for (const user of this.users.values()) {
			if (user.email.toLowerCase() === email.toLowerCase()) {
				return user;
			}
		}
		return null;
	}

	async create(
		email: string,
		password: string,
		roles: string[] = []
	): Promise<User> {
		if (await this.findByEmail(email)) {
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			_id: crypto.randomUUID(),
			email,
			verified: false,
			password,
			active: true,
			roles,
			createdAt: now,
			updatedAt: now,
			lastLoginAt: null
		};
		this.users.set(user._id, user);
		return user;
	}

	async list(): Promise<User[]> {
		return [...this.users.values()];
	}

	async update(
		_id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password'>>
	): Promise<User | null> {
		const user = this.users.get(_id);
		if (!user) return null;
		Object.assign(user, patch, { updatedAt: new Date() });
		return user;
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/user_store.spec.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Update `lib/adapters/mongodb/userStore.ts`**

Add `roles` to the inserted document, return the created `User`, and add `list`/`update`:

```ts
	async create(
		email: string,
		password: string,
		roles: string[] = []
	): Promise<User> {
		const existingUser = await this.findByEmail(email);
		if (existingUser) {
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			_id: crypto.randomUUID().replaceAll('-', ''),
			email: email.toLowerCase(),
			verified: false,
			password,
			active: true,
			roles,
			createdAt: now,
			updatedAt: now,
			lastLoginAt: null
		};
		await db.collection<User>(this.prefix + this.name).insertOne(user);
		return user;
	}

	async list(): Promise<User[]> {
		return db.collection<User>(this.prefix + this.name).find().toArray();
	}

	async update(
		_id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password'>>
	): Promise<User | null> {
		return db
			.collection<User>(this.prefix + this.name)
			.findOneAndUpdate(
				{ _id },
				{ $set: { ...patch, updatedAt: new Date() } },
				{ returnDocument: 'after' }
			);
	}
```

- [ ] **Step 7: Fix the one existing `create` caller**

`lib/interactions/index.ts` calls `await getUserStore().create(body.email, ...)` and ignores the return — still valid (return type widened to `Promise<User>`). No change needed unless typecheck complains. Run:

Run: `bun run typecheck`
Expected: no new errors. If `User` construction elsewhere fails for missing `roles`, add `roles: []` there.

- [ ] **Step 8: Format + commit**

```bash
bun run format
git add lib/adapters lib/interactions test/admin/user_store.spec.ts
git commit -m "feat(admin): user roles + list/update store methods"
```

---

## Task 4: Admin-session store

**Files:**

- Modify: `lib/adapters/types.ts`, `lib/adapters/memory/index.ts`, `lib/adapters/mongodb/index.ts`, `lib/adapters/index.ts`
- Create: `lib/adapters/memory/adminSessionStore.ts`, `lib/adapters/mongodb/adminSessionStore.ts`
- Test: `test/admin/admin_session_store.spec.ts`

**Interfaces:**

- Produces: `AdminSession`, `AdminSessionStoreInstance`, `adminSessionStore` (singleton instance).

- [ ] **Step 1: Add types to `lib/adapters/types.ts`**

```ts
export interface AdminSession {
	_id: string;
	userId: string;
	bucketId: string;
	tokens: { accessToken?: string; idToken?: string; refreshToken?: string };
	createdAt: Date;
	expiresAt: Date;
	absoluteExpiresAt: Date;
}

export interface AdminSessionStoreInstance {
	create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession>;
	find(id: string): Promise<AdminSession | null>;
	touch(id: string, ttlSeconds: number): Promise<void>;
	destroy(id: string): Promise<void>;
}

export interface AdminSessionStoreConstructor {
	new (): AdminSessionStoreInstance;
}
```

- [ ] **Step 2: Write the failing test `test/admin/admin_session_store.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { AdminSessionStore } from 'lib/adapters/memory/adminSessionStore.ts';

describe('AdminSessionStore (memory)', () => {
	let store: AdminSessionStore;
	beforeEach(() => {
		store = new AdminSessionStore();
	});

	it('creates, finds, touches and destroys', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			tokens: { idToken: 'x' },
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toMatchObject({ userId: 'u1' });
		const before = (await store.find(s._id))!.expiresAt.getTime();
		await store.touch(s._id, 120);
		expect((await store.find(s._id))!.expiresAt.getTime()).toBeGreaterThan(
			before
		);
		await store.destroy(s._id);
		expect(await store.find(s._id)).toBeNull();
	});

	it('returns null for an expired session', async () => {
		const s = await store.create({
			userId: 'u1',
			bucketId: 'admin',
			tokens: {},
			ttlSeconds: -1,
			absoluteTtlSeconds: 3600
		});
		expect(await store.find(s._id)).toBeNull();
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/admin_session_store.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `lib/adapters/memory/adminSessionStore.ts`**

```ts
import type { AdminSession, AdminSessionStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class AdminSessionStore implements AdminSessionStoreInstance {
	private sessions = new Map<string, AdminSession>();

	async create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession> {
		const now = new Date();
		const session: AdminSession = {
			_id: nanoid(),
			userId: data.userId,
			bucketId: data.bucketId,
			tokens: data.tokens,
			createdAt: now,
			expiresAt: new Date(now.getTime() + data.ttlSeconds * 1000),
			absoluteExpiresAt: new Date(
				now.getTime() + data.absoluteTtlSeconds * 1000
			)
		};
		this.sessions.set(session._id, session);
		return session;
	}

	async find(id: string): Promise<AdminSession | null> {
		const s = this.sessions.get(id);
		if (!s) return null;
		const now = Date.now();
		if (s.expiresAt.getTime() <= now || s.absoluteExpiresAt.getTime() <= now) {
			this.sessions.delete(id);
			return null;
		}
		return s;
	}

	async touch(id: string, ttlSeconds: number): Promise<void> {
		const s = this.sessions.get(id);
		if (!s) return;
		const next = new Date(Date.now() + ttlSeconds * 1000);
		s.expiresAt =
			next.getTime() > s.absoluteExpiresAt.getTime()
				? s.absoluteExpiresAt
				: next;
	}

	async destroy(id: string): Promise<void> {
		this.sessions.delete(id);
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/admin_session_store.spec.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Implement `lib/adapters/mongodb/adminSessionStore.ts`**

```ts
import { db } from './db.js';
import type { AdminSession, AdminSessionStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class AdminSessionStore implements AdminSessionStoreInstance {
	private collection = db.collection<AdminSession>('adminSession');

	async create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession> {
		const now = new Date();
		const session: AdminSession = {
			_id: nanoid(),
			userId: data.userId,
			bucketId: data.bucketId,
			tokens: data.tokens,
			createdAt: now,
			expiresAt: new Date(now.getTime() + data.ttlSeconds * 1000),
			absoluteExpiresAt: new Date(
				now.getTime() + data.absoluteTtlSeconds * 1000
			)
		};
		await this.collection.insertOne(session);
		return session;
	}

	async find(id: string): Promise<AdminSession | null> {
		const s = await this.collection.findOne({ _id: id });
		if (!s) return null;
		const now = Date.now();
		if (s.expiresAt.getTime() <= now || s.absoluteExpiresAt.getTime() <= now) {
			await this.collection.deleteOne({ _id: id });
			return null;
		}
		return s;
	}

	async touch(id: string, ttlSeconds: number): Promise<void> {
		const s = await this.collection.findOne({ _id: id });
		if (!s) return;
		const next = new Date(Date.now() + ttlSeconds * 1000);
		const expiresAt =
			next.getTime() > s.absoluteExpiresAt.getTime()
				? s.absoluteExpiresAt
				: next;
		await this.collection.updateOne({ _id: id }, { $set: { expiresAt } });
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
```

The `adminSession` collection gets a TTL index on `expiresAt` in Task 5.

- [ ] **Step 7: Export + wire a shared singleton in `lib/adapters/index.ts`**

Export `AdminSessionStore` from both memory/mongodb index files. In `lib/adapters/index.ts`, mirror the JWKS pattern (a ready instance, not a getter):

```ts
let AdminSessionStoreClass: AdminSessionStoreConstructor =
	MemoryAdminSessionStore;
// inside the MONGODB_URI block:
AdminSessionStoreClass = mongodb.AdminSessionStore;

export const adminSessionStore: AdminSessionStoreInstance =
	new AdminSessionStoreClass();
```

- [ ] **Step 8: Run + format + commit**

```bash
bun test test/admin/admin_session_store.spec.ts && bun run format
git add lib/adapters test/admin/admin_session_store.spec.ts
git commit -m "feat(admin): admin-session store with sliding + absolute TTL"
```

---

## Task 5: Constants, collections & seeding

**Files:**

- Create: `lib/admin/consts.ts`
- Modify: `database/collections.ts`, `database/mongodb.ts`
- Create: `lib/admin/seed.ts` (shared idempotent seed used by both `db:setup` and runtime)
- Test: `test/admin/seed.spec.ts`

**Interfaces:**

- Consumes: `getProjectStore`, `getBucketStore` (Tasks 1–2), `provider.Client` namespace, `ClientDefaults`.
- Produces: `ADMIN_PROJECT_ID`, `ADMIN_BUCKET_ID`, `ADMIN_CLIENT_ID`, `ADMIN_SESSION_COOKIE`; `ensureAdminSeed(): Promise<void>`.

- [ ] **Step 1: Create `lib/admin/consts.ts`**

```ts
export const ADMIN_PROJECT_ID = 'admin';
export const ADMIN_BUCKET_ID = 'admin';
export const ADMIN_CLIENT_ID = 'admin-panel';
export const ADMIN_SESSION_COOKIE = '_admin_session';

export const ADMIN_SESSION_TTL_SECONDS = 60 * 60; // sliding
export const ADMIN_SESSION_ABSOLUTE_TTL_SECONDS = 60 * 60 * 12; // hard cap
```

- [ ] **Step 2: Add collections in `database/collections.ts`**

Add `'projects'`, `'userBuckets'`, `'adminSession'` to the `COLLECTIONS` array (do not remove existing entries).

- [ ] **Step 3: Give `adminSession` a TTL index in `database/mongodb.ts`**

In the index-creation loop, the non-`jwks` branch already adds `{ key: { expiresAt: 1 }, expireAfterSeconds: 0 }`, which covers `adminSession`. Add a `projects` uniqueness index by extending the loop:

```ts
			...(name === 'projects'
				? [
						{
							key: { slug: 1 },
							unique: true
						}
					]
				: []),
```

- [ ] **Step 4: Write the failing test `test/admin/seed.spec.ts`**

```ts
import { describe, it, expect } from 'bun:test';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore, getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_PROJECT_ID, ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { provider } from 'lib/provider.ts';

describe('ensureAdminSeed', () => {
	it('is idempotent and seeds admin project + bucket + client', async () => {
		provider.init({ clients: [], adapter: undefined });
		await ensureAdminSeed();
		await ensureAdminSeed();
		const project = await getProjectStore().find(ADMIN_PROJECT_ID);
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		expect(project).toMatchObject({ type: 'admin', bucketId: ADMIN_BUCKET_ID });
		expect(bucket?.roles).toEqual(['super_admin', 'project_admin']);
		expect(await provider.Client.find(ADMIN_CLIENT_ID)).toBeTruthy();
	});
});
```

Note: `provider.init` here is the minimal shape used by other specs; if a required option is missing the runner will report it — supply the same defaults `test/*/default.config.ts` uses.

- [ ] **Step 5: Run test to verify it fails**

Run: `bun test test/admin/seed.spec.ts`
Expected: FAIL — `lib/admin/seed.ts` not found.

- [ ] **Step 6: Implement `lib/admin/seed.ts`**

```ts
import { getProjectStore, getBucketStore } from '../adapters/index.js';
import { provider } from '../provider.js';
import { ISSUER } from '../configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from './consts.js';

export async function ensureAdminSeed(): Promise<void> {
	const buckets = getBucketStore();
	if (!(await buckets.find(ADMIN_BUCKET_ID))) {
		await buckets.create({
			_id: ADMIN_BUCKET_ID,
			name: 'Administrators',
			managedBy: [],
			roles: ['super_admin', 'project_admin'],
			authMethods: ['password']
		});
	}

	const projects = getProjectStore();
	if (!(await projects.find(ADMIN_PROJECT_ID))) {
		await projects.create({
			_id: ADMIN_PROJECT_ID,
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			managedBy: [],
			bucketId: ADMIN_BUCKET_ID
		});
	}

	if (!(await provider.Client.find(ADMIN_CLIENT_ID))) {
		await provider.Client.adapter.upsert(ADMIN_CLIENT_ID, {
			clientId: ADMIN_CLIENT_ID,
			applicationType: 'web',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`${ISSUER}/admin/callback`],
			'token.endpointAuthMethod': 'none',
			'consent.require': false
		});
	}
}
```

Note: confirm the exact client-metadata key names against `lib/configs/clientSchema.ts` while implementing (e.g. the auth-method and consent keys) and match them; the fields above mirror `ClientDefaults`. `provider.Client.adapter` is the client adapter exposed by the `provider.Client` namespace.

- [ ] **Step 7: Call the seed from `database/mongodb.ts`**

At the end of `database/mongodb.ts` (before `dbClient.close()`), the seed needs the mongo stores. Because `database/mongodb.ts` runs as a standalone script with its own `db` connection, seed via direct collection writes there rather than importing the app singletons, to avoid a second connection. Add:

```ts
const now = new Date();
await db.collection('userBuckets').updateOne(
	{ _id: 'admin' },
	{
		$setOnInsert: {
			name: 'Administrators',
			managedBy: [],
			roles: ['super_admin', 'project_admin'],
			authMethods: ['password'],
			createdAt: now,
			updatedAt: now
		}
	},
	{ upsert: true }
);
await db.collection('projects').updateOne(
	{ _id: 'admin' },
	{
		$setOnInsert: {
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			managedBy: [],
			bucketId: 'admin',
			createdAt: now,
			updatedAt: now
		}
	},
	{ upsert: true }
);
await db.collection('Client').updateOne(
	{ _id: 'admin-panel' },
	{
		$setOnInsert: {
			payload: {
				clientId: 'admin-panel',
				applicationType: 'web',
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: [`${process.env.ISSUER}/admin/callback`],
				'token.endpointAuthMethod': 'none',
				'consent.require': false
			}
		}
	},
	{ upsert: true }
);
```

Match the `Client` document shape to how `provider.Client.adapter` persists clients (inspect one existing client doc). Adjust the wrapping (`payload`) to match.

- [ ] **Step 8: Run test + format**

Run: `bun test test/admin/seed.spec.ts && bun run format`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add lib/admin/consts.ts lib/admin/seed.ts database test/admin/seed.spec.ts
git commit -m "feat(admin): reserved constants, collections, idempotent seed"
```

---

## Task 6: RBAC middleware

**Files:**

- Create: `lib/admin/auth/rbac.ts`
- Test: `test/admin/rbac.spec.ts`

**Interfaces:**

- Consumes: `adminSessionStore` (Task 4), `getUserStore` (Task 3), `getProjectStore`/`getBucketStore` (Tasks 1–2), consts (Task 5).
- Produces:
  - `resolveAdmin` — Elysia plugin (scoped `.derive`) attaching `admin: AdminContext | null`.
  - `AdminContext = { userId: string; roles: string[]; bucketId: string; managedProjectIds: string[] }`.
  - `assertAuth(admin) => AdminContext` (throws `AdminError` 401 if null).
  - `assertRole(admin, role)`, `assertProjectAccess(admin, project)`, `assertBucketAccess(admin, bucket)`.
  - `class AdminError extends Error { status: number }`.

- [ ] **Step 1: Write the failing test `test/admin/rbac.spec.ts`**

```ts
import { describe, it, expect } from 'bun:test';
import {
	assertRole,
	assertProjectAccess,
	AdminError,
	type AdminContext
} from 'lib/admin/auth/rbac.ts';
import type { Project } from 'lib/adapters/types.ts';

const superAdmin: AdminContext = {
	userId: 'u1',
	roles: ['super_admin'],
	bucketId: 'admin',
	managedProjectIds: []
};
const projectAdmin: AdminContext = {
	userId: 'u2',
	roles: ['project_admin'],
	bucketId: 'admin',
	managedProjectIds: ['p1']
};
const project = (over: Partial<Project>): Project => ({
	_id: 'p1',
	name: 'Acme',
	slug: 'acme',
	type: 'regular',
	managedBy: ['u2'],
	bucketId: null,
	createdAt: new Date(),
	updatedAt: new Date(),
	...over
});

describe('RBAC guards', () => {
	it('assertRole passes for super_admin, throws 403 otherwise', () => {
		expect(() => assertRole(superAdmin, 'super_admin')).not.toThrow();
		try {
			assertRole(projectAdmin, 'super_admin');
			throw new Error('should have thrown');
		} catch (e) {
			expect((e as AdminError).status).toBe(403);
		}
	});

	it('project admin can access managed regular project', () => {
		expect(() => assertProjectAccess(projectAdmin, project({}))).not.toThrow();
	});

	it('project admin cannot access the admin project even by id', () => {
		try {
			assertProjectAccess(
				projectAdmin,
				project({ type: 'admin', managedBy: ['u2'] })
			);
			throw new Error('should have thrown');
		} catch (e) {
			expect((e as AdminError).status).toBe(403);
		}
	});

	it('super admin can access any project', () => {
		expect(() =>
			assertProjectAccess(superAdmin, project({ type: 'admin', managedBy: [] }))
		).not.toThrow();
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/rbac.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `lib/admin/auth/rbac.ts`**

```ts
import { Elysia } from 'elysia';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from '../../adapters/index.js';
import type { Project, UserBucket } from '../../adapters/types.js';
import { ADMIN_SESSION_COOKIE, ADMIN_SESSION_TTL_SECONDS } from '../consts.js';

export interface AdminContext {
	userId: string;
	roles: string[];
	bucketId: string;
	managedProjectIds: string[];
}

export class AdminError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

export function assertAuth(admin: AdminContext | null): AdminContext {
	if (!admin) throw new AdminError(401, 'authentication required');
	return admin;
}

export function assertRole(admin: AdminContext, role: string): void {
	if (!admin.roles.includes(role)) {
		throw new AdminError(403, `role ${role} required`);
	}
}

export function assertProjectAccess(
	admin: AdminContext,
	project: Project
): void {
	if (admin.roles.includes('super_admin')) return;
	if (project.type === 'admin' || !project.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this project');
	}
}

export function assertBucketAccess(
	admin: AdminContext,
	bucket: UserBucket
): void {
	if (admin.roles.includes('super_admin')) return;
	if (!bucket.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this bucket');
	}
}

export const resolveAdmin = new Elysia({ name: 'admin-resolve' }).derive(
	{ as: 'scoped' },
	async ({ cookie }): Promise<{ admin: AdminContext | null }> => {
		const sessionId = cookie[ADMIN_SESSION_COOKIE]?.value;
		if (!sessionId) return { admin: null };
		const session = await adminSessionStore.find(sessionId);
		if (!session) return { admin: null };
		const user = await getUserStore(session.bucketId).find(session.userId);
		if (!user || !user.active) return { admin: null };
		await adminSessionStore.touch(sessionId, ADMIN_SESSION_TTL_SECONDS);
		const managed = await getProjectStore().listByManager(user._id);
		return {
			admin: {
				userId: user._id,
				roles: user.roles,
				bucketId: session.bucketId,
				managedProjectIds: managed.map((p) => p._id)
			}
		};
	}
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/rbac.spec.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Format + commit**

```bash
bun run format
git add lib/admin/auth/rbac.ts test/admin/rbac.spec.ts
git commit -m "feat(admin): RBAC context resolver + role/project/bucket guards"
```

---

## Task 7: First-run setup endpoint

**Files:**

- Create: `lib/admin/auth/setup.ts`
- Test: `test/admin/setup.spec.ts`

**Interfaces:**

- Consumes: `getUserStore` (Task 3), consts (Task 5), `ensureAdminSeed` (Task 5), `AdminError` (Task 6).
- Produces: `adminSetup` Elysia plugin with `GET /admin/setup`, `POST /admin/api/setup`, and helper `hasSuperAdmin(): Promise<boolean>`.

- [ ] **Step 1: Write the failing test `test/admin/setup.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminSetup, hasSuperAdmin } from 'lib/admin/auth/setup.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

const app = new Elysia().use(adminSetup);
const client = treaty(app);

describe('first-run setup', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates the first super_admin then hard-gates', async () => {
		expect(await hasSuperAdmin()).toBe(false);
		const first = await client.admin.api.setup.post({
			email: 'root@x.io',
			password: 'correct horse battery'
		});
		expect(first.status).toBe(201);
		const user = await getUserStore(ADMIN_BUCKET_ID).findByEmail('root@x.io');
		expect(user?.roles).toEqual(['super_admin']);

		const second = await client.admin.api.setup.post({
			email: 'evil@x.io',
			password: 'nope nope nope'
		});
		expect(second.status).toBe(409);
		expect(await hasSuperAdmin()).toBe(true);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/setup.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `lib/admin/auth/setup.ts`**

```ts
import { Elysia, t } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../consts.js';

export async function hasSuperAdmin(): Promise<boolean> {
	const users = await getUserStore(ADMIN_BUCKET_ID).list();
	return users.some((u) => u.roles.includes('super_admin'));
}

export const adminSetup = new Elysia({ name: 'admin-setup' })
	.get('/admin/setup', async ({ redirect }) => {
		if (await hasSuperAdmin()) {
			return redirect('/admin/login', 302);
		}
		return new Response(
			'<!doctype html><meta charset=utf-8><div id=root></div><script src="/admin.js"></script>',
			{ headers: { 'content-type': 'text/html; charset=utf-8' } }
		);
	})
	.post(
		'/admin/api/setup',
		async ({ body, set }) => {
			if (await hasSuperAdmin()) {
				set.status = 409;
				return { error: 'already_initialized', message: 'setup is closed' };
			}
			const hash = await Bun.password.hash(body.password);
			await getUserStore(ADMIN_BUCKET_ID).create(body.email, hash, [
				'super_admin'
			]);
			set.status = 201;
			return { ok: true };
		},
		{
			body: t.Object({
				email: t.String({ format: 'email' }),
				password: t.String({ minLength: 12 })
			})
		}
	);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/setup.spec.ts`
Expected: PASS.

- [ ] **Step 5: Format + commit**

```bash
bun run format
git add lib/admin/auth/setup.ts test/admin/setup.spec.ts
git commit -m "feat(admin): hard-gated first-run super-admin setup"
```

---

## Task 8: Projects API

**Files:**

- Create: `lib/admin/projects/schema.ts`, `lib/admin/projects/routes.ts`
- Test: `test/admin/projects_routes.spec.ts`

**Interfaces:**

- Consumes: `resolveAdmin`, guards, `AdminError` (Task 6); `getProjectStore`, `getBucketStore` (Tasks 1–2).
- Produces: `projectRoutes` Elysia plugin. Routes (all under `/admin/api`):
  `GET /projects`, `POST /projects`, `GET /projects/:id`, `PATCH /projects/:id`, `DELETE /projects/:id`, `PUT /projects/:id/bucket`.

- [ ] **Step 1: Create `lib/admin/projects/schema.ts`**

```ts
import { t } from 'elysia';

export const CreateProjectBody = t.Object({
	name: t.String({ minLength: 1 }),
	slug: t.String({ pattern: '^[a-z0-9-]+$' }),
	managedBy: t.Optional(t.Array(t.String()))
});

export const UpdateProjectBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	managedBy: t.Optional(t.Array(t.String()))
});

export const SetBucketBody = t.Object({
	bucketId: t.String()
});
```

- [ ] **Step 2: Write the failing test `test/admin/projects_routes.spec.ts`**

Use a harness that injects a fixed admin by stubbing the session cookie via a seeded session. To keep the test focused on routing/authorization, mount `resolveAdmin` + `projectRoutes` on a bare app and seed an admin session directly.

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminSessionStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(projectRoutes);
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

describe('projects API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access with 401', async () => {
		const res = await client.admin.api.projects.get();
		expect(res.status).toBe(401);
	});

	it('super_admin creates and lists projects', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const created = await client.admin.api.projects.post(
			{ name: 'Acme', slug: 'acme' },
			{ headers: { cookie } }
		);
		expect(created.status).toBe(201);
		const list = await client.admin.api.projects.get({ headers: { cookie } });
		expect(list.data?.some((p) => p.slug === 'acme')).toBe(true);
	});

	it('project_admin sees only managed projects and cannot create', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		await client.admin.api.projects.post(
			{ name: 'Mine', slug: 'mine', managedBy: [pa.userId] },
			{ headers: { cookie: superSession.cookie } }
		);
		await client.admin.api.projects.post(
			{ name: 'Other', slug: 'other' },
			{ headers: { cookie: superSession.cookie } }
		);
		const list = await client.admin.api.projects.get({
			headers: { cookie: pa.cookie }
		});
		expect(list.data?.map((p) => p.slug)).toEqual(['mine']);
		const denied = await client.admin.api.projects.post(
			{ name: 'X', slug: 'x' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(denied.status).toBe(403);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/projects_routes.spec.ts`
Expected: FAIL — `projectRoutes` not found.

- [ ] **Step 4: Implement `lib/admin/projects/routes.ts`**

```ts
import { Elysia } from 'elysia';
import { getProjectStore, getBucketStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	assertProjectAccess,
	AdminError,
	type AdminContext
} from '../auth/rbac.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody
} from './schema.js';

async function loadProject(id: string) {
	const project = await getProjectStore().find(id);
	if (!project) throw new AdminError(404, 'project not found');
	return project;
}

export const projectRoutes = new Elysia({ name: 'admin-projects' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'forbidden', message: error.message };
		}
	})
	.get('/admin/api/projects', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getProjectStore();
		const all = ctx.roles.includes('super_admin')
			? (await store.list()).filter((p) => p.type === 'regular')
			: await store.listByManager(ctx.userId);
		return all;
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const store = getProjectStore();
			if (await store.findBySlug(body.slug)) {
				throw new AdminError(409, 'slug already exists');
			}
			const project = await store.create({
				name: body.name,
				slug: body.slug,
				type: 'regular',
				managedBy: body.managedBy ?? []
			});
			set.status = 201;
			return project;
		},
		{ body: CreateProjectBody }
	)
	.get('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const project = await loadProject(params.id);
		assertProjectAccess(ctx, project);
		return project;
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(params.id);
			assertProjectAccess(ctx, project);
			if (body.managedBy !== undefined) assertRole(ctx, 'super_admin');
			return getProjectStore().update(params.id, body);
		},
		{ body: UpdateProjectBody }
	)
	.delete('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		const project = await loadProject(params.id);
		if (project.type === 'admin')
			throw new AdminError(403, 'cannot delete admin project');
		await getProjectStore().destroy(params.id);
		return { ok: true };
	})
	.put(
		'/admin/api/projects/:id/bucket',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(params.id);
			assertProjectAccess(ctx, project);
			const bucket = await getBucketStore().find(body.bucketId);
			if (!bucket) throw new AdminError(404, 'bucket not found');
			return getProjectStore().update(params.id, { bucketId: body.bucketId });
		},
		{ body: SetBucketBody }
	);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/projects_routes.spec.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Format + commit**

```bash
bun run format
git add lib/admin/projects test/admin/projects_routes.spec.ts
git commit -m "feat(admin): project CRUD + bucket assignment API"
```

---

## Task 9: Admin-accounts API

**Files:**

- Create: `lib/admin/users/schema.ts`, `lib/admin/users/routes.ts`
- Test: `test/admin/admins_routes.spec.ts`

**Interfaces:**

- Consumes: `resolveAdmin`, guards (Task 6); `getUserStore` (Task 3); consts (Task 5).
- Produces: `adminUserRoutes` plugin. Routes (super_admin only): `GET /admin/api/admins`, `POST /admin/api/admins`, `PATCH /admin/api/admins/:id`, `DELETE /admin/api/admins/:id` (soft — sets `active:false`).

- [ ] **Step 1: Create `lib/admin/users/schema.ts`**

```ts
import { t } from 'elysia';

export const CreateAdminBody = t.Object({
	email: t.String({ format: 'email' }),
	password: t.String({ minLength: 12 }),
	roles: t.Array(
		t.Union([t.Literal('super_admin'), t.Literal('project_admin')])
	)
});

export const UpdateAdminBody = t.Object({
	roles: t.Optional(
		t.Array(t.Union([t.Literal('super_admin'), t.Literal('project_admin')]))
	),
	active: t.Optional(t.Boolean())
});
```

- [ ] **Step 2: Write the failing test `test/admin/admins_routes.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminSessionStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(adminUserRoutes);
const client = treaty(app);

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${Math.random()}@x.io`,
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
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

describe('admin-accounts API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('super_admin creates a project_admin', async () => {
		const cookie = await cookieFor(['super_admin']);
		const res = await client.admin.api.admins.post(
			{
				email: 'pa@x.io',
				password: 'correct horse battery',
				roles: ['project_admin']
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = await getUserStore(ADMIN_BUCKET_ID).findByEmail('pa@x.io');
		expect(created?.roles).toEqual(['project_admin']);
	});

	it('project_admin is forbidden', async () => {
		const cookie = await cookieFor(['project_admin']);
		const res = await client.admin.api.admins.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/admins_routes.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `lib/admin/users/routes.ts`**

```ts
import { Elysia } from 'elysia';
import { getUserStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { CreateAdminBody, UpdateAdminBody } from './schema.js';

const store = () => getUserStore(ADMIN_BUCKET_ID);

export const adminUserRoutes = new Elysia({ name: 'admin-users' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'forbidden', message: error.message };
		}
	})
	.get('/admin/api/admins', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return (await store().list()).map(({ password: _password, ...u }) => u);
	})
	.post(
		'/admin/api/admins',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			if (await store().findByEmail(body.email)) {
				throw new AdminError(409, 'email already exists');
			}
			const hash = await Bun.password.hash(body.password);
			const user = await store().create(body.email, hash, body.roles);
			set.status = 201;
			const { password: _password, ...safe } = user;
			return safe;
		},
		{ body: CreateAdminBody }
	)
	.patch(
		'/admin/api/admins/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const updated = await store().update(params.id, body);
			if (!updated) throw new AdminError(404, 'admin not found');
			const { password: _password, ...safe } = updated;
			return safe;
		},
		{ body: UpdateAdminBody }
	)
	.delete('/admin/api/admins/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		if (params.id === ctx.userId) {
			throw new AdminError(409, 'cannot deactivate yourself');
		}
		const updated = await store().update(params.id, { active: false });
		if (!updated) throw new AdminError(404, 'admin not found');
		return { ok: true };
	});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/admins_routes.spec.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Format + commit**

```bash
bun run format
git add lib/admin/users test/admin/admins_routes.spec.ts
git commit -m "feat(admin): admin-account CRUD (super_admin only)"
```

---

## Task 10: Buckets API

**Files:**

- Create: `lib/admin/buckets/schema.ts`, `lib/admin/buckets/routes.ts`
- Test: `test/admin/buckets_routes.spec.ts`

**Interfaces:**

- Consumes: guards (Task 6); `getBucketStore` (Task 2), `getProjectStore` (Task 1).
- Produces: `bucketRoutes` plugin: `GET /admin/api/buckets`, `POST /admin/api/buckets`, `DELETE /admin/api/buckets/:id`.

- [ ] **Step 1: Create `lib/admin/buckets/schema.ts`**

```ts
import { t } from 'elysia';

export const CreateBucketBody = t.Object({
	name: t.String({ minLength: 1 }),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String()))
});
```

- [ ] **Step 2: Write the failing test `test/admin/buckets_routes.spec.ts`**

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

describe('buckets API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a standalone bucket', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Dev users', roles: ['viewer'] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		expect(res.data?.authMethods).toEqual(['password']);
	});

	it('refuses to delete a bucket still referenced by a project', async () => {
		const cookie = await superCookie();
		const bucket = await client.admin.api.buckets.post(
			{ name: 'Shared' },
			{ headers: { cookie } }
		);
		const project = await getProjectStore().create({ name: 'P', slug: 'p' });
		await getProjectStore().update(project._id, { bucketId: bucket.data!._id });
		const res = await client.admin.api
			.buckets({ id: bucket.data!._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(409);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/buckets_routes.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `lib/admin/buckets/routes.ts`**

```ts
import { Elysia } from 'elysia';
import { getBucketStore, getProjectStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	assertBucketAccess,
	AdminError,
	type AdminContext
} from '../auth/rbac.js';
import { CreateBucketBody } from './schema.js';

export const bucketRoutes = new Elysia({ name: 'admin-buckets' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'forbidden', message: error.message };
		}
	})
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getBucketStore();
		return ctx.roles.includes('super_admin')
			? store.list()
			: store.listByManager(ctx.userId);
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			const bucket = await getBucketStore().create({
				name: body.name,
				roles: body.roles ?? [],
				managedBy: body.managedBy ?? [ctx.userId]
			});
			set.status = 201;
			return bucket;
		},
		{ body: CreateBucketBody }
	)
	.delete('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await getBucketStore().find(params.id);
		if (!bucket) throw new AdminError(404, 'bucket not found');
		assertBucketAccess(ctx, bucket);
		if ((await getProjectStore().countByBucket(params.id)) > 0) {
			throw new AdminError(409, 'bucket is assigned to one or more projects');
		}
		await getBucketStore().destroy(params.id);
		return { ok: true };
	});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/buckets_routes.spec.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Format + commit**

```bash
bun run format
git add lib/admin/buckets test/admin/buckets_routes.spec.ts
git commit -m "feat(admin): standalone bucket API with referential delete guard"
```

---

## Task 11: OIDC login (BFF) + session + mount

**Files:**

- Create: `lib/admin/auth/session.ts`, `lib/admin/auth/login.ts`, `lib/admin/index.ts`
- Modify: `lib/interactions/index.ts`, `lib/index.ts`
- Test: `test/admin/login_flow.spec.ts`

**Interfaces:**

- Consumes: `adminSessionStore`, consts, `resolveAdmin`, all route plugins, `adminSetup`.
- Produces: `adminApp` Elysia plugin (mounts everything under `/admin`); `/admin/login`, `/admin/callback`, `/admin/api/logout`, `/admin/api/me`.

- [ ] **Step 1: Implement `lib/admin/auth/session.ts`**

```ts
import { adminSessionStore } from '../../adapters/index.js';
import {
	ADMIN_SESSION_COOKIE,
	ADMIN_SESSION_TTL_SECONDS,
	ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
} from '../consts.js';
import type { AdminSession } from '../../adapters/types.js';

export async function createAdminSession(data: {
	userId: string;
	bucketId: string;
	tokens: AdminSession['tokens'];
}) {
	return adminSessionStore.create({
		...data,
		ttlSeconds: ADMIN_SESSION_TTL_SECONDS,
		absoluteTtlSeconds: ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
	});
}

export function sessionCookieAttributes() {
	return {
		httpOnly: true,
		sameSite: 'strict' as const,
		secure: true,
		path: '/admin',
		maxAge: ADMIN_SESSION_TTL_SECONDS
	};
}

export const SESSION_COOKIE_NAME = ADMIN_SESSION_COOKIE;
```

- [ ] **Step 2: Special-case the admin bucket in `lib/interactions/index.ts`**

In the `POST ui/:uid/login` handler, the user store is currently `getUserStore()` (default `redfox`). Resolve the bucket from the interaction's client so the admin-panel client authenticates against the admin bucket:

```ts
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from 'lib/admin/consts.js';
// ...
const clientId = interaction.payload.params?.client_id;
const bucketId = clientId === ADMIN_CLIENT_ID ? ADMIN_BUCKET_ID : undefined;
const userStore = getUserStore(bucketId);
```

(Leaving `bucketId` undefined keeps the current default `redfox` behaviour for all other clients — the general client→bucket binding lands in SP-2/SP-3.)

- [ ] **Step 3: Implement `lib/admin/auth/login.ts`**

Public client + PKCE. The BFF stores the code_verifier + state in a short-lived signed cookie between `/admin/login` and `/admin/callback`; token exchange is an internal POST to the server's own `/token`.

```ts
import { Elysia, t } from 'elysia';
import crypto from 'node:crypto';
import { ISSUER } from '../../configs/env.js';
import { getUserStore, adminSessionStore } from '../../adapters/index.js';
import { createAdminSession, sessionCookieAttributes } from './session.js';
import {
	ADMIN_CLIENT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE
} from '../consts.js';

const REDIRECT_URI = `${ISSUER}/admin/callback`;

function base64url(buf: Buffer) {
	return buf.toString('base64url');
}

export const adminLogin = new Elysia({ name: 'admin-login' })
	.get('/admin/login', ({ cookie, redirect }) => {
		const verifier = base64url(crypto.randomBytes(32));
		const challenge = base64url(
			crypto.createHash('sha256').update(verifier).digest()
		);
		const state = base64url(crypto.randomBytes(16));
		cookie.admin_oauth.set({
			value: JSON.stringify({ verifier, state }),
			httpOnly: true,
			sameSite: 'lax',
			secure: true,
			path: '/admin',
			maxAge: 600
		});
		const url = new URL(`${ISSUER}/authorize`);
		url.search = new URLSearchParams({
			client_id: ADMIN_CLIENT_ID,
			response_type: 'code',
			redirect_uri: REDIRECT_URI,
			scope: 'openid',
			state,
			code_challenge: challenge,
			code_challenge_method: 'S256'
		}).toString();
		return redirect(url.toString(), 302);
	})
	.get(
		'/admin/callback',
		async ({ query, cookie, redirect, set }) => {
			const saved = cookie.admin_oauth.value
				? JSON.parse(cookie.admin_oauth.value)
				: null;
			cookie.admin_oauth.remove();
			if (!saved || saved.state !== query.state) {
				set.status = 400;
				return { error: 'invalid_state', message: 'state mismatch' };
			}
			const res = await fetch(`${ISSUER}/token`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: query.code,
					redirect_uri: REDIRECT_URI,
					client_id: ADMIN_CLIENT_ID,
					code_verifier: saved.verifier
				})
			});
			if (!res.ok) {
				set.status = 401;
				return { error: 'token_exchange_failed', message: 'login failed' };
			}
			const tokens = (await res.json()) as {
				access_token: string;
				id_token: string;
				refresh_token?: string;
			};
			const sub = JSON.parse(
				Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString()
			).sub as string;
			const user = await getUserStore(ADMIN_BUCKET_ID).find(sub);
			if (!user || !user.active) {
				set.status = 403;
				return { error: 'not_admin', message: 'no admin account' };
			}
			const session = await createAdminSession({
				userId: user._id,
				bucketId: ADMIN_BUCKET_ID,
				tokens: {
					accessToken: tokens.access_token,
					idToken: tokens.id_token,
					refreshToken: tokens.refresh_token
				}
			});
			cookie[ADMIN_SESSION_COOKIE].set({
				value: session._id,
				...sessionCookieAttributes()
			});
			return redirect('/admin', 302);
		},
		{ query: t.Object({ code: t.String(), state: t.String() }) }
	)
	.post('/admin/api/logout', async ({ cookie }) => {
		const id = cookie[ADMIN_SESSION_COOKIE]?.value;
		if (id) await adminSessionStore.destroy(id);
		cookie[ADMIN_SESSION_COOKIE].remove();
		return { ok: true };
	});
```

- [ ] **Step 4: Implement `lib/admin/index.ts` (aggregate + `/me` + JSON error scope)**

```ts
import { Elysia } from 'elysia';
import {
	resolveAdmin,
	assertAuth,
	AdminError,
	type AdminContext
} from './auth/rbac.js';
import { adminSetup } from './auth/setup.js';
import { adminLogin } from './auth/login.js';
import { projectRoutes } from './projects/routes.js';
import { adminUserRoutes } from './users/routes.js';
import { bucketRoutes } from './buckets/routes.js';

export const adminApp = new Elysia({ name: 'admin' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.use(adminSetup)
	.use(adminLogin)
	.use(resolveAdmin)
	.get('/admin/api/me', ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return ctx;
	})
	.use(projectRoutes)
	.use(adminUserRoutes)
	.use(bucketRoutes);
```

- [ ] **Step 5: Mount in `lib/index.ts`**

Import and `.use(adminApp)` in the Elysia chain (after `.use(nocache)`, before `.listen`). Add `import { adminApp } from './admin/index.js';`.

- [ ] **Step 6: Write the failing integration test `test/admin/login_flow.spec.ts`**

This drives the full dance against the real app. Bootstrap with a config that enables dev interactions and registers the admin-panel client; seed a super_admin; follow `/admin/login` → `/authorize` → post credentials → `/admin/callback`; assert a session cookie and that `/admin/api/me` returns the roles.

```ts
import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

const { agent } = await import('../test_helper.ts');

describe('admin OIDC login (BFF)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta);
		await ensureAdminSeed();
		await getUserStore(ADMIN_BUCKET_ID).create(
			'root@x.io',
			await Bun.password.hash('correct horse battery'),
			['super_admin']
		);
	});

	it('me is 401 without a session', async () => {
		const res = await agent.admin.api.me.get();
		expect(res.status).toBe(401);
	});

	// Full redirect-following login is exercised here; drive /admin/login,
	// extract the interaction uid from the Location header, POST credentials to
	// /ui/:uid/login, follow the resume redirect to /admin/callback, then assert
	// /admin/api/me returns { roles: ['super_admin'] } with the returned cookie.
});
```

Create `test/admin/admin.config.ts` exporting `config` (with `devInteractions.enabled: true`) and `clients: [{ clientId: 'admin-panel', tokenEndpointAuthMethod: 'none', grantTypes: ['authorization_code'], responseTypes: ['code'], redirectUris: ['<ISSUER>/admin/callback'] }]`. Match the client field names to `clientSchema.ts`.

- [ ] **Step 7: Implement the full login-flow assertion**

Flesh out the commented section: use `fetch`/`agent` to follow 302s manually (Eden/`fetch` with `redirect: 'manual'`), parse the `Location` header for the interaction `uid`, POST form-encoded credentials via `jsonToFormUrlEncoded`, carry the `_interaction`/`_session` cookies, and finally read `_admin_session` from the callback response `Set-Cookie`. Assert `agent.admin.api.me.get({ headers: { cookie } })` returns `data.roles` containing `super_admin`.

- [ ] **Step 8: Run test to verify it passes**

Run: `bun test test/admin/login_flow.spec.ts`
Expected: PASS.

- [ ] **Step 9: Run the entire suite (regression gate) + format**

Run: `bun test && bun run format`
Expected: PASS — existing end-user login and all prior suites unaffected.

- [ ] **Step 10: Commit**

```bash
git add lib/admin lib/interactions/index.ts lib/index.ts test/admin
git commit -m "feat(admin): OIDC/BFF login, session, /me, mount admin app"
```

---

## Task 12: React app shell

**Files:**

- Create: `lib/admin/ui/serverRender.tsx`, `lib/admin/ui/adminClient.tsx`, `lib/admin/ui/pages/{Layout,Setup,Projects,Admins,Stub}.tsx`, `lib/admin/ui/htmlTemplate.html`
- Modify: `lib/admin/index.ts` (serve the SPA for `/admin` and unmatched `/admin/*` non-api paths), `package.json`
- Test: `test/admin/ui_shell.spec.ts`

**Interfaces:**

- Consumes: `hasSuperAdmin` (Task 7); `/admin/api/*` (Tasks 8–11).
- Produces: bundled `public/admin.js`; SPA served at `/admin`.

- [ ] **Step 1: Add the build target in `package.json`**

Change `build`/`watch` to also bundle the admin client:

```json
		"build": "bun build --outdir=public --minify ./lib/interactions/loginClient.tsx ./lib/admin/ui/adminClient.tsx",
		"watch": "bun build --outdir=public --minify ./lib/interactions/loginClient.tsx ./lib/admin/ui/adminClient.tsx --watch",
```

- [ ] **Step 2: Create `lib/admin/ui/htmlTemplate.html`**

```html
<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<meta
			name="viewport"
			content="width=device-width, initial-scale=1"
		/>
		<title>OAuth Admin</title>
	</head>
	<body>
		<div id="root"><!--app-html--></div>
		<!--app-props-->
		<script src="/admin.js"></script>
	</body>
</html>
```

- [ ] **Step 3: Create the pages**

`lib/admin/ui/pages/Stub.tsx`:

```tsx
import { Result } from 'antd';

export function Stub({ title }: { title: string }) {
	return (
		<Result
			status="info"
			title={title}
			subTitle="Coming soon"
		/>
	);
}
```

`lib/admin/ui/pages/Layout.tsx` — an Ant Design `Layout` with a role-aware sider (Projects always; Admins/Settings/Keys only when `roles` includes `super_admin`), reading `window.PROPS.me`. `Setup.tsx` — an Ant Design `Form` POSTing to `/admin/api/setup`. `Projects.tsx` — a `Table` fed by `GET /admin/api/projects` with a create modal. `Admins.tsx` — a `Table` fed by `GET /admin/api/admins`. Keep each file focused; import antd components directly. (Full component code authored during implementation; each is a straightforward antd view — no server logic.)

- [ ] **Step 4: Create `lib/admin/ui/adminClient.tsx`**

```tsx
import { hydrateRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { Layout } from './pages/Layout.tsx';
import { Setup } from './pages/Setup.tsx';

declare global {
	interface Window {
		PROPS?: { needsSetup?: boolean; me?: unknown };
	}
}

const props = window.PROPS || {};

hydrateRoot(
	document.getElementById('root') as HTMLElement,
	<StrictMode>{props.needsSetup ? <Setup /> : <Layout />}</StrictMode>
);
```

- [ ] **Step 5: Create `lib/admin/ui/serverRender.tsx`**

```tsx
import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import { Layout } from './pages/Layout.js';
import { Setup } from './pages/Setup.js';

const template = Bun.file('./lib/admin/ui/htmlTemplate.html');

export async function renderAdminShell(props: {
	needsSetup: boolean;
	me: unknown;
}) {
	let html = await template.text();
	html = html
		.replace(
			'<!--app-props-->',
			`<script>window.PROPS=${JSON.stringify(props)}</script>`
		)
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>{props.needsSetup ? <Setup /> : <Layout />}</StrictMode>
			)
		);
	return new Response(html, {
		headers: { 'content-type': 'text/html; charset=utf-8' }
	});
}
```

- [ ] **Step 6: Serve the shell from `lib/admin/index.ts`**

Add a catch-all GET for `/admin` that renders the shell. When no super_admin exists, render with `needsSetup: true`; otherwise, if there's no valid admin session, redirect to `/admin/login`; else render `needsSetup: false` with `me`:

```ts
import { renderAdminShell } from './ui/serverRender.js';
import { hasSuperAdmin } from './auth/setup.js';
// within adminApp, after resolveAdmin:
	.get('/admin', async ({ admin, redirect }) => {
		if (!(await hasSuperAdmin())) {
			return renderAdminShell({ needsSetup: true, me: null });
		}
		if (!admin) return redirect('/admin/login', 302);
		return renderAdminShell({ needsSetup: false, me: admin });
	})
```

- [ ] **Step 7: Write the test `test/admin/ui_shell.spec.ts`**

```ts
import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';

describe('admin UI shell', () => {
	beforeAll(async () => {
		await bootstrap(import.meta, { config: 'admin' });
	});

	it('serves the setup screen when no super_admin exists', async () => {
		const res = await agent.admin.get();
		const html = await res.response.text();
		expect(res.response.headers.get('content-type')).toContain('text/html');
		expect(html).toContain('window.PROPS');
		expect(html).toContain('"needsSetup":true');
	});
});
```

(This suite relies on a fresh in-memory adapter with no seeded super_admin. If the seed created one in an earlier suite within the same process, run this spec's bootstrap with a cleared store; `TestAdapter.clear()` runs in `bootstrap`, and the memory user store for the admin bucket starts empty per process — assert accordingly.)

- [ ] **Step 8: Run test + build + format**

Run: `bun test test/admin/ui_shell.spec.ts && bun run build && bun run format`
Expected: PASS; `public/admin.js` produced.

- [ ] **Step 9: Commit**

```bash
git add lib/admin/ui lib/admin/index.ts package.json test/admin/ui_shell.spec.ts public/admin.js
git commit -m "feat(admin): React app shell (setup, layout, projects, admins)"
```

---

## Task 13: Full-suite regression + typecheck gate

**Files:** none (verification task)

- [ ] **Step 1: Typecheck**

Run: `bun run typecheck`
Expected: no errors.

- [ ] **Step 2: Full test suite**

Run: `bun test`
Expected: all suites pass, including pre-existing ones (no regression from the `lib/interactions/index.ts` and `lib/adapters/*` changes).

- [ ] **Step 3: Lint/format**

Run: `bun run format`
Expected: clean.

- [ ] **Step 4: Commit any formatting deltas**

```bash
git add -A
git commit -m "chore(admin): typecheck + full-suite green for SP-1"
```

---

## Self-Review

**Spec coverage:**

- Data model (§4): `projects` (Task 1), `userBuckets` (Task 2), user `roles` + per-bucket collections (Task 3), `adminSession` (Task 4). ✔
- OIDC/BFF auth (§5): Task 11 (login/callback/session) + admin-bucket special-case. ✔
- RBAC (§6): Task 6 (`resolveAdmin`, `requireRole`/`assertRole`, project + bucket access). ✔
- API surface (§7): auth/session + `/me` (Task 11), setup (Task 7), projects (Task 8), admins (Task 9), buckets (Task 10). ✔
- Bootstrap & seeding (§8): Task 5 (`db:setup` + `ensureAdminSeed`) + first-run setup (Task 7). ✔
- UI shell (§9): Task 12. ✔
- Module layout (§10): matches the created files. ✔
- Testing (§11): each task ships specs; Task 13 is the regression gate. ✔
- Risks (§12): login-flow coupling covered by Task 11 Step 9 full-suite run; bucket-delete referential check in Task 10; per-bucket collections via `getUserStore(bucketId)`.

**Deviation from spec (intentional):** §5 mentions a `roles` claim in the ID token. With BFF, `resolveAdmin` reads roles from the DB by `sub`, so SP-1 does **not** add a `roles` claim — this reduces coupling to the claims config and the OAuth token pipeline. Flagged for the reviewer; revisit only if a non-BFF consumer needs roles in the token.

**Placeholder scan:** UI component bodies in Task 12 Step 3 are described rather than fully coded — they are pure antd views with no server logic and are the one place where full inline code adds little planning value; every server-side unit has complete code. All other steps contain runnable code and exact commands.

**Type consistency:** `AdminContext`, `Project`, `UserBucket`, `AdminSession`, and store method names (`create`/`find`/`findBySlug`/`listByManager`/`update`/`destroy`/`countByBucket`) are used identically across tasks. `create` on the user store returns `Promise<User>` everywhere it's consumed.

**Open implementation confirmations (resolve while coding, not blockers):**

- Exact client-metadata key names for the seeded panel client (`token.endpointAuthMethod` / `consent.require`) against `lib/configs/clientSchema.ts`.
- The `Client` document wrapping shape used by `provider.Client.adapter` for the raw-mongo seed in `database/mongodb.ts`.
