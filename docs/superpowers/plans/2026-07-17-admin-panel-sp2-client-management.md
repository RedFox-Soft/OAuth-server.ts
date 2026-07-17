# Admin Panel SP-2 — Project-scoped Client Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Manage OAuth clients per project from the admin panel — clients are associated to a project via `Project.clientIds`, with project-scoped CRUD + secret rotation and a per-project UI.

**Architecture:** The client→project link lives on the admin-layer `Project` (`clientIds: string[]`); the protocol `Client` model is unchanged. A thin admin service creates/updates/deletes protocol clients through the existing `Client.validateClient` + `Client.adapter` path (same validation as dynamic registration), translating between an SPA-friendly camelCase body and the client model's canonical keys. Routes are nested under `/admin/api/projects/:id/clients`, guarded by SP-1 RBAC. The UI is a drill-down from the Projects table.

**Tech Stack:** Bun, Elysia, TypeBox, MongoDB + memory adapters, React 19 + Ant Design 6, bun:test + Eden treaty.

## Global Constraints

- Protocol `Client` model, `/authorize`, `/token`, discovery, `/reg` — **unchanged**. SP-2 adds only admin-layer code.
- A `clientId` belongs to **exactly one** project (enforced in the admin API, not storage).
- Client secret is returned to the caller **once** (on create and on rotate); never re-readable via GET/list.
- The reserved `admin-panel` client (in the reserved `admin` project) is **not** manageable via these routes.
- Ownership scoping: a client is only reachable through the project that owns it (`:clientId` must be in `:id`'s `clientIds`), even for `super_admin`.
- Follow SP-1 patterns exactly: `AdminError` + `admin_error` shape, `resolveAdmin`/`assertAuth`/`assertProjectAccess`, `nanoid` ids, memory + mongodb store parity.
- TDD, DRY, YAGNI, one commit per task. Tests run with `bun test`.

---

### Task 1: `Project.clientIds` in the model + both stores

**Files:**
- Modify: `lib/adapters/types.ts` (Project interface + ProjectStoreInstance)
- Modify: `lib/adapters/memory/projectStore.ts`
- Modify: `lib/adapters/mongodb/projectStore.ts`
- Test: `test/admin/project_store.spec.ts`

**Interfaces:**
- Produces: `Project.clientIds: string[]`; `ProjectStore.create({..., clientIds?})` defaults `[]`; `ProjectStore.update(id, { clientIds })` supported.

- [ ] **Step 1: Write the failing test** — append to `test/admin/project_store.spec.ts`:

```ts
it('defaults clientIds to [] and updates them', async () => {
	const store = getProjectStore();
	const p = await store.create({ name: 'C', slug: `c-${Math.random()}` });
	expect(p.clientIds).toEqual([]);
	const updated = await store.update(p._id, { clientIds: ['abc'] });
	expect(updated?.clientIds).toEqual(['abc']);
	const reloaded = await store.find(p._id);
	expect(reloaded?.clientIds).toEqual(['abc']);
});
```

(If `getProjectStore` / imports aren't already in the file, mirror the existing imports at its top.)

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/project_store.spec.ts -t "clientIds"`
Expected: FAIL (`clientIds` is `undefined`).

- [ ] **Step 3: Implement — types.** In `lib/adapters/types.ts`:

Add to the `Project` interface (after `bucketId`):
```ts
	clientIds: string[];
```
In `ProjectStoreInstance.create`'s param object add:
```ts
		clientIds?: string[];
```
In `ProjectStoreInstance.update`'s patch type, extend the Pick:
```ts
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId' | 'clientIds'>>
```

- [ ] **Step 4: Implement — memory store.** In `lib/adapters/memory/projectStore.ts`:

In `create`, add `clientIds` to both the param type and the built object:
```ts
			clientIds: data.clientIds ?? [],
```
Extend the `update` patch Pick to include `'clientIds'` (mirror the types.ts change).

- [ ] **Step 5: Implement — mongodb store.** In `lib/adapters/mongodb/projectStore.ts`: apply the identical `create` (`clientIds: data.clientIds ?? []`) and `update` Pick changes.

- [ ] **Step 6: Run test to verify it passes**

Run: `bun test test/admin/project_store.spec.ts -t "clientIds"`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add lib/adapters/types.ts lib/adapters/memory/projectStore.ts lib/adapters/mongodb/projectStore.ts test/admin/project_store.spec.ts
git commit -m "feat(admin): add clientIds to Project model + stores"
```

---

### Task 2: Seed the admin project with `clientIds: ['admin-panel']`

**Files:**
- Modify: `lib/admin/seed.ts`
- Test: `test/admin/seed.spec.ts`

**Interfaces:**
- Consumes: `ADMIN_CLIENT_ID` from `lib/admin/consts.ts` (already imported in seed.ts).
- Produces: after `ensureAdminSeed()`, the admin project's `clientIds` contains `ADMIN_CLIENT_ID`.

- [ ] **Step 1: Write the failing test** — append to `test/admin/seed.spec.ts`:

```ts
it('seeds the admin project with the panel client id', async () => {
	await ensureAdminSeed();
	const project = await getProjectStore().find(ADMIN_PROJECT_ID);
	expect(project?.clientIds).toContain(ADMIN_CLIENT_ID);
});
```

Ensure the file imports `getProjectStore` (from `lib/adapters/index.ts`) and `ADMIN_PROJECT_ID`, `ADMIN_CLIENT_ID` (from `lib/admin/consts.ts`); add any that are missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/seed.spec.ts -t "panel client id"`
Expected: FAIL (`clientIds` is `[]`).

- [ ] **Step 3: Implement.** In `lib/admin/seed.ts`, in the `projects.create` call for the admin project, add:
```ts
			clientIds: [ADMIN_CLIENT_ID],
```
Then handle a pre-existing admin project that predates this field — replace the `if (!(await projects.find(ADMIN_PROJECT_ID)))` block so it backfills:
```ts
	const existingAdminProject = await projects.find(ADMIN_PROJECT_ID);
	if (!existingAdminProject) {
		await projects.create({
			_id: ADMIN_PROJECT_ID,
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			managedBy: [],
			bucketId: ADMIN_BUCKET_ID,
			clientIds: [ADMIN_CLIENT_ID]
		});
	} else if (!existingAdminProject.clientIds.includes(ADMIN_CLIENT_ID)) {
		await projects.update(ADMIN_PROJECT_ID, {
			clientIds: [...existingAdminProject.clientIds, ADMIN_CLIENT_ID]
		});
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/seed.spec.ts`
Expected: PASS (all seed tests).

- [ ] **Step 5: Commit**

```bash
git add lib/admin/seed.ts test/admin/seed.spec.ts
git commit -m "feat(admin): seed admin project clientIds with panel client"
```

---

### Task 3: Admin client service + request/response schemas

**Files:**
- Create: `lib/admin/clients/service.ts`
- Create: `lib/admin/clients/schema.ts`
- Test: `test/admin/client_service.spec.ts`

**Interfaces:**
- Produces:
  - `AdminClientView` — the API/UI client shape: `{ clientId: string; clientName?: string; applicationType: string; grantTypes: string[]; responseTypes: string[]; redirectUris: string[]; postLogoutRedirectUris: string[]; tokenEndpointAuthMethod: string; scope?: string; requireConsent: boolean }`
  - `createClient(input: CreateClientInput): Promise<{ view: AdminClientView; secret?: string }>` — generates `clientId` (nanoid), derives `responseTypes` from `grantTypes`, generates a secret iff the resolved auth method needs one, validates via `Client.validateClient`, stores via `Client.adapter.upsert`. Returns the view + the plaintext secret (once) if generated.
  - `updateClient(clientId, patch): Promise<AdminClientView>` — re-validates the merged metadata and re-stores; preserves existing secret.
  - `rotateSecret(clientId): Promise<string>` — generates + stores a new secret, returns it; throws `AdminError(400)` if the client is public (no secret).
  - `getClientView(clientId): Promise<AdminClientView | null>`
  - `deleteClientRecord(clientId): Promise<void>` — `Client.adapter.destroy`.
- Consumes: `Client` (`validateClient`, `needsSecret`, `tryFind`, `adapter`) from `lib/models/client.js`; `nanoid` from `lib/helpers/nanoid.js`; `AdminError` from `lib/admin/auth/rbac.js`.

- [ ] **Step 1: Write the schemas.** Create `lib/admin/clients/schema.ts`:

```ts
import { t } from 'elysia';

// Grant types the provider supports (discovery grant_types_supported). The UI
// offers this full set (SP-2 decision: "all supported grants"); validateClient +
// the token endpoint's hasGrant gating remain the runtime source of truth.
export const SUPPORTED_GRANT_TYPES = [
	'authorization_code',
	'refresh_token',
	'client_credentials',
	'urn:ietf:params:oauth:grant-type:device_code',
	'urn:openid:params:grant-type:ciba'
] as const;

const AUTH_METHODS = [
	'none',
	'client_secret_basic',
	'client_secret_post'
] as const;

export const CreateClientBody = t.Object({
	clientName: t.Optional(t.String({ minLength: 1 })),
	applicationType: t.Optional(
		t.Union([t.Literal('web'), t.Literal('native')])
	),
	grantTypes: t.Array(t.Union(SUPPORTED_GRANT_TYPES.map((g) => t.Literal(g))), {
		minItems: 1
	}),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: t.Union(AUTH_METHODS.map((m) => t.Literal(m))),
	scope: t.Optional(t.String())
});

export const UpdateClientBody = t.Object({
	clientName: t.Optional(t.String({ minLength: 1 })),
	applicationType: t.Optional(
		t.Union([t.Literal('web'), t.Literal('native')])
	),
	grantTypes: t.Optional(
		t.Array(t.Union(SUPPORTED_GRANT_TYPES.map((g) => t.Literal(g))), {
			minItems: 1
		})
	),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: t.Optional(
		t.Union(AUTH_METHODS.map((m) => t.Literal(m)))
	),
	scope: t.Optional(t.String())
});
```

- [ ] **Step 2: Write the failing test.** Create `test/admin/client_service.spec.ts`:

```ts
import { describe, it, expect } from 'bun:test';
import {
	createClient,
	getClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord
} from 'lib/admin/clients/service.ts';

describe('admin client service', () => {
	it('creates a public client (no secret) with derived response types', async () => {
		const { view, secret } = await createClient({
			clientName: 'SPA',
			applicationType: 'web',
			grantTypes: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://app.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		expect(view.clientId).toBeTruthy();
		expect(view.responseTypes).toEqual(['code']);
		expect(secret).toBeUndefined();
		const reloaded = await getClientView(view.clientId);
		expect(reloaded?.clientName).toBe('SPA');
	});

	it('creates a confidential client and returns the secret once', async () => {
		const { view, secret } = await createClient({
			clientName: 'Server',
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(secret).toBeTruthy();
		// secret is never echoed back through the view
		expect((view as Record<string, unknown>).clientSecret).toBeUndefined();
		const rotated = await rotateSecret(view.clientId);
		expect(rotated).toBeTruthy();
		expect(rotated).not.toBe(secret);
		await deleteClientRecord(view.clientId);
		expect(await getClientView(view.clientId)).toBeNull();
	});

	it('rejects rotating the secret of a public client', async () => {
		const { view } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://a.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		await expect(rotateSecret(view.clientId)).rejects.toThrow();
	});

	it('updates redirect uris and preserves the secret', async () => {
		const { view, secret } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://one.example.com/cb'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(secret).toBeTruthy();
		const updated = await updateClient(view.clientId, {
			redirectUris: ['https://two.example.com/cb']
		});
		expect(updated.redirectUris).toEqual(['https://two.example.com/cb']);
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test test/admin/client_service.spec.ts`
Expected: FAIL (`lib/admin/clients/service.ts` does not exist).

- [ ] **Step 4: Implement the service.** Create `lib/admin/clients/service.ts`:

```ts
import crypto from 'node:crypto';
import nanoid from '../../helpers/nanoid.js';
import { Client } from '../../models/client.js';
import { AdminError } from '../auth/rbac.js';

export interface AdminClientView {
	clientId: string;
	clientName?: string;
	applicationType: string;
	grantTypes: string[];
	responseTypes: string[];
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	tokenEndpointAuthMethod: string;
	scope?: string;
	requireConsent: boolean;
}

export interface CreateClientInput {
	clientName?: string;
	applicationType?: 'web' | 'native';
	grantTypes: string[];
	redirectUris?: string[];
	postLogoutRedirectUris?: string[];
	tokenEndpointAuthMethod: string;
	scope?: string;
}

export type UpdateClientInput = Partial<CreateClientInput>;

function generateSecret(): string {
	return crypto.randomBytes(48).toString('base64url');
}

function responseTypesFor(grantTypes: string[]): string[] {
	return grantTypes.includes('authorization_code') ? ['code'] : [];
}

// Build the canonical metadata object that Client.validateClient expects: base
// attributes use canonical camelCase (redirectUris/grantTypes/…), recognized
// metadata uses snake_case (token_endpoint_auth_method/scope/…), plus the dotted
// `consent.require` key. Mirrors the boundary translation in actions/registration.ts.
function toMetadata(input: CreateClientInput, clientId: string) {
	const metadata: Record<string, unknown> = {
		clientId,
		applicationType: input.applicationType ?? 'web',
		grantTypes: input.grantTypes,
		responseTypes: responseTypesFor(input.grantTypes),
		redirectUris: input.redirectUris ?? [],
		post_logout_redirect_uris: input.postLogoutRedirectUris ?? [],
		token_endpoint_auth_method: input.tokenEndpointAuthMethod,
		'consent.require': false
	};
	if (input.clientName !== undefined) metadata.client_name = input.clientName;
	if (input.scope !== undefined) metadata.scope = input.scope;
	return metadata;
}

function toView(client: {
	clientId: string;
	clientName?: string;
	applicationType?: string;
	grantTypes?: string[];
	responseTypes?: string[];
	redirectUris?: string[];
	postLogoutRedirectUris?: string[];
	tokenEndpointAuthMethod?: string;
	scope?: string;
	['consent.require']?: boolean;
}): AdminClientView {
	return {
		clientId: client.clientId,
		clientName: client.clientName,
		applicationType: client.applicationType ?? 'web',
		grantTypes: client.grantTypes ?? [],
		responseTypes: client.responseTypes ?? [],
		redirectUris: client.redirectUris ?? [],
		postLogoutRedirectUris: client.postLogoutRedirectUris ?? [],
		tokenEndpointAuthMethod: client.tokenEndpointAuthMethod ?? 'none',
		scope: client.scope,
		requireConsent: client['consent.require'] !== false
	};
}

async function validateAndStore(metadata: Record<string, unknown>) {
	// Client.validateClient throws InvalidClient on bad metadata; the route layer
	// maps that to HTTP 422.
	const client = Client.validateClient(metadata);
	await Client.adapter.upsert(client.clientId, client.metadata());
	return client;
}

export async function createClient(
	input: CreateClientInput
): Promise<{ view: AdminClientView; secret?: string }> {
	const clientId = nanoid();
	const metadata = toMetadata(input, clientId);
	let secret: string | undefined;
	if (Client.needsSecret(metadata)) {
		secret = generateSecret();
		metadata.clientSecret = secret;
		metadata.client_secret_expires_at = 0;
	}
	const client = await validateAndStore(metadata);
	return { view: toView(client as never), secret };
}

export async function getClientView(
	clientId: string
): Promise<AdminClientView | null> {
	const client = await Client.tryFind(clientId);
	return client ? toView(client as never) : null;
}

export async function updateClient(
	clientId: string,
	patch: UpdateClientInput
): Promise<AdminClientView> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	const merged: CreateClientInput = {
		clientName: patch.clientName ?? existing.clientName,
		applicationType: (patch.applicationType ??
			existing.applicationType ??
			'web') as 'web' | 'native',
		grantTypes: patch.grantTypes ?? existing.grantTypes ?? [],
		redirectUris: patch.redirectUris ?? existing.redirectUris ?? [],
		postLogoutRedirectUris:
			patch.postLogoutRedirectUris ?? existing.postLogoutRedirectUris ?? [],
		tokenEndpointAuthMethod:
			patch.tokenEndpointAuthMethod ??
			existing.tokenEndpointAuthMethod ??
			'none',
		scope: patch.scope ?? existing.scope
	};
	const metadata = toMetadata(merged, clientId);
	// preserve an existing secret across metadata updates
	if (existing.clientSecret) {
		metadata.clientSecret = existing.clientSecret;
		metadata.client_secret_expires_at = existing.clientSecretExpiresAt ?? 0;
	}
	const client = await validateAndStore(metadata);
	return toView(client as never);
}

export async function rotateSecret(clientId: string): Promise<string> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	if (!existing.clientSecret) {
		throw new AdminError(400, 'client has no secret to rotate');
	}
	const secret = generateSecret();
	const metadata = { ...existing.metadata(), clientSecret: secret };
	await validateAndStore(metadata as Record<string, unknown>);
	return secret;
}

export async function deleteClientRecord(clientId: string): Promise<void> {
	await Client.adapter.destroy(clientId);
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/client_service.spec.ts`
Expected: PASS (4 tests). If `Client.validateClient` rejects a metadata shape, fix `toMetadata` to match what `actions/registration.ts` produces (canonical base keys, snake recognized keys) — do not change the client model.

- [ ] **Step 6: Commit**

```bash
git add lib/admin/clients/service.ts lib/admin/clients/schema.ts test/admin/client_service.spec.ts
git commit -m "feat(admin): client service (create/update/rotate/delete) + schemas"
```

---

### Task 4: Project-scoped client routes + wire into adminApp

**Files:**
- Create: `lib/admin/clients/routes.ts`
- Modify: `lib/admin/index.ts` (add `.use(clientRoutes)`)
- Test: `test/admin/clients_routes.spec.ts`

**Interfaces:**
- Consumes: service from Task 3; `Project.clientIds` from Task 1; `resolveAdmin`, `assertAuth`, `assertProjectAccess`, `AdminError`, `AdminContext` from `lib/admin/auth/rbac.js`; `getProjectStore` from `lib/adapters/index.js`; `ADMIN_CLIENT_ID` from `lib/admin/consts.js`; `CreateClientBody`/`UpdateClientBody` from Task 3.
- Produces: `clientRoutes` (Elysia plugin) mounted by `adminApp`.

- [ ] **Step 1: Write the failing test.** Create `test/admin/clients_routes.spec.ts` (mirror `projects_routes.spec.ts` harness):

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(projectRoutes).use(clientRoutes);
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

async function makeProject(managedBy: string[] = []) {
	return getProjectStore().create({
		name: 'P',
		slug: `p-${Math.random()}`,
		managedBy
	});
}

describe('clients API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access', async () => {
		const proj = await makeProject();
		const res = await client.admin.api
			.projects({ id: proj._id })
			.clients.get();
		expect(res.status).toBe(401);
	});

	it('creates, lists, and links a client to the project', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					clientName: 'SPA',
					grantTypes: ['authorization_code'],
					redirectUris: ['https://a.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
		const body = created.data as { clientId: string; secret?: string };
		expect(body.clientId).toBeTruthy();
		expect(body.secret).toBeUndefined(); // public client
		const reloaded = await getProjectStore().find(proj._id);
		expect(reloaded?.clientIds).toContain(body.clientId);
		const list = await client.admin.api
			.projects({ id: proj._id })
			.clients.get({ headers: { cookie } });
		const clients = list.data as Array<{ clientId: string }>;
		expect(clients.some((c) => c.clientId === body.clientId)).toBe(true);
	});

	it('returns a confidential secret once on create, never on GET', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['client_credentials'],
					tokenEndpointAuthMethod: 'client_secret_basic'
				},
				{ headers: { cookie } }
			);
		const body = created.data as { clientId: string; secret?: string };
		expect(body.secret).toBeTruthy();
		const one = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: body.clientId })
			.get({ headers: { cookie } });
		expect((one.data as Record<string, unknown>).secret).toBeUndefined();
		expect((one.data as Record<string, unknown>).clientSecret).toBeUndefined();
	});

	it('maps invalid client metadata to 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		// authorization_code with no redirect_uris is invalid
		const res = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{ grantTypes: ['authorization_code'], tokenEndpointAuthMethod: 'none' },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(422);
	});

	it('scopes project_admin to managed projects and 404s cross-project reads', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const mine = await makeProject([pa.userId]);
		const other = await makeProject();
		// create a client in `other` as super_admin
		const created = await client.admin.api
			.projects({ id: other._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://x.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie: su.cookie } }
			);
		const otherClientId = (created.data as { clientId: string }).clientId;
		// project_admin cannot list `other`
		const denied = await client.admin.api
			.projects({ id: other._id })
			.clients.get({ headers: { cookie: pa.cookie } });
		expect(denied.status).toBe(403);
		// even via a project they DO manage, the foreign clientId 404s
		const wrong = await client.admin.api
			.projects({ id: mine._id })
			.clients({ clientId: otherClientId })
			.get({ headers: { cookie: pa.cookie } });
		expect(wrong.status).toBe(404);
	});

	it('refuses to manage the reserved admin-panel client', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.projects({ id: ADMIN_PROJECT_ID })
			.clients({ clientId: ADMIN_CLIENT_ID })
			.delete(undefined, { headers: { cookie } });
		expect(res.status === 403 || res.status === 404).toBe(true);
	});

	it('deletes a client and unlinks it from the project', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://d.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		const id = (created.data as { clientId: string }).clientId;
		const del = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: id })
			.delete(undefined, { headers: { cookie } });
		expect(del.status).toBe(200);
		const reloaded = await getProjectStore().find(proj._id);
		expect(reloaded?.clientIds).not.toContain(id);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/clients_routes.spec.ts`
Expected: FAIL (`lib/admin/clients/routes.ts` does not exist).

- [ ] **Step 3: Implement the routes.** Create `lib/admin/clients/routes.ts`:

```ts
import { Elysia } from 'elysia';
import { getProjectStore } from '../../adapters/index.js';
import { InvalidClient } from '../../helpers/errors.js';
import {
	assertAuth,
	assertProjectAccess,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_CLIENT_ID } from '../consts.js';
import { CreateClientBody, UpdateClientBody } from './schema.js';
import {
	createClient,
	getClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord
} from './service.js';

// Load a REGULAR project the caller may access, or throw. Client management never
// applies to the reserved admin project.
async function loadManageableProject(admin: AdminContext, id: string) {
	const project = await getProjectStore().find(id);
	if (!project) throw new AdminError(404, 'project not found');
	if (project.type === 'admin')
		throw new AdminError(403, 'cannot manage admin project clients');
	assertProjectAccess(admin, project);
	return project;
}

// Ownership scoping: the client id must belong to this project.
function assertOwnsClient(project: { clientIds: string[] }, clientId: string) {
	if (clientId === ADMIN_CLIENT_ID)
		throw new AdminError(403, 'cannot manage the reserved admin client');
	if (!project.clientIds.includes(clientId))
		throw new AdminError(404, 'client not found in this project');
}

export const clientRoutes = new Elysia({ name: 'admin-clients' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
		// Client metadata validation failure → 422.
		if (error instanceof InvalidClient) {
			set.status = 422;
			return { error: 'invalid_client_metadata', message: error.message };
		}
	})
	.get('/admin/api/projects/:id/clients', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const project = await loadManageableProject(ctx, params.id);
		const views = [];
		for (const clientId of project.clientIds) {
			const view = await getClientView(clientId);
			if (view) views.push(view);
		}
		return views;
	})
	.post(
		'/admin/api/projects/:id/clients',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			const { view, secret } = await createClient(body);
			await getProjectStore().update(params.id, {
				clientIds: [...project.clientIds, view.clientId]
			});
			set.status = 201;
			return { ...view, secret };
		},
		{ body: CreateClientBody }
	)
	.get(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			const view = await getClientView(params.clientId);
			if (!view) throw new AdminError(404, 'client not found');
			return view;
		}
	)
	.patch(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			return updateClient(params.clientId, body);
		},
		{ body: UpdateClientBody }
	)
	.post(
		'/admin/api/projects/:id/clients/:clientId/secret',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			const secret = await rotateSecret(params.clientId);
			return { clientId: params.clientId, secret };
		}
	)
	.delete(
		'/admin/api/projects/:id/clients/:clientId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadManageableProject(ctx, params.id);
			assertOwnsClient(project, params.clientId);
			await deleteClientRecord(params.clientId);
			await getProjectStore().update(params.id, {
				clientIds: project.clientIds.filter((c) => c !== params.clientId)
			});
			return { ok: true };
		}
	);
```

- [ ] **Step 4: Wire into adminApp.** In `lib/admin/index.ts`:

Add the import near the other route imports:
```ts
import { clientRoutes } from './clients/routes.js';
```
Add to the chain after `.use(projectRoutes)`:
```ts
	.use(clientRoutes)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/clients_routes.spec.ts`
Expected: PASS (7 tests). If the `InvalidClient` import path differs, confirm with `grep -n "class InvalidClient" lib/helpers/errors.ts`.

- [ ] **Step 6: Commit**

```bash
git add lib/admin/clients/routes.ts lib/admin/index.ts test/admin/clients_routes.spec.ts
git commit -m "feat(admin): project-scoped client CRUD + rotate routes"
```

---

### Task 5: UI — project Clients drill-down

**Files:**
- Create: `lib/admin/ui/pages/Clients.tsx`
- Modify: `lib/admin/ui/pages/Projects.tsx` (row action → open Clients view)
- Build: `bun build.ts`

**Interfaces:**
- Consumes: the Task 4 REST endpoints under `/admin/api/projects/:id/clients`.
- Produces: `Clients` React component `Clients({ project, onBack }: { project: Project; onBack: () => void })`.

- [ ] **Step 1: Implement the Clients page.** Create `lib/admin/ui/pages/Clients.tsx`:

```tsx
import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Typography,
	Popconfirm,
	message
} from 'antd';
import { PlusOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import type { Project } from '../../../adapters/types.js';

const GRANT_OPTIONS = [
	{ label: 'authorization_code', value: 'authorization_code' },
	{ label: 'refresh_token', value: 'refresh_token' },
	{ label: 'client_credentials', value: 'client_credentials' },
	{
		label: 'device_code',
		value: 'urn:ietf:params:oauth:grant-type:device_code'
	},
	{ label: 'ciba', value: 'urn:openid:params:grant-type:ciba' }
];
const AUTH_OPTIONS = [
	{ label: 'none (public / PKCE)', value: 'none' },
	{ label: 'client_secret_basic', value: 'client_secret_basic' },
	{ label: 'client_secret_post', value: 'client_secret_post' }
];

interface ClientView {
	clientId: string;
	clientName?: string;
	applicationType: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris: string[];
}
interface FormValues {
	clientName?: string;
	applicationType: 'web' | 'native';
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris?: string;
	scope?: string;
}

export function Clients({
	project,
	onBack
}: {
	project: Project;
	onBack: () => void;
}) {
	const base = `/admin/api/projects/${project._id}/clients`;
	const [rows, setRows] = useState<ClientView[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [secret, setSecret] = useState<string | null>(null);
	const [form] = Form.useForm<FormValues>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch(base);
			if (res.ok) setRows((await res.json()) as ClientView[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [project._id]);

	async function onCreate(values: FormValues) {
		setSaving(true);
		try {
			const res = await fetch(base, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					clientName: values.clientName,
					applicationType: values.applicationType,
					grantTypes: values.grantTypes,
					tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
					redirectUris: (values.redirectUris ?? '')
						.split('\n')
						.map((s) => s.trim())
						.filter(Boolean),
					scope: values.scope
				})
			});
			const body = (await res.json().catch(() => null)) as
				| { message?: string; secret?: string }
				| null;
			if (!res.ok) {
				message.error(body?.message || 'failed to create client');
				return;
			}
			setOpen(false);
			form.resetFields();
			if (body?.secret) setSecret(body.secret);
			await load();
		} finally {
			setSaving(false);
		}
	}

	async function onDelete(clientId: string) {
		const res = await fetch(`${base}/${encodeURIComponent(clientId)}`, {
			method: 'DELETE'
		});
		if (!res.ok) {
			message.error('failed to delete client');
			return;
		}
		await load();
	}

	async function onRotate(clientId: string) {
		const res = await fetch(
			`${base}/${encodeURIComponent(clientId)}/secret`,
			{ method: 'POST' }
		);
		const body = (await res.json().catch(() => null)) as {
			secret?: string;
		} | null;
		if (!res.ok || !body?.secret) {
			message.error('failed to rotate secret');
			return;
		}
		setSecret(body.secret);
	}

	return (
		<>
			<Space style={{ marginBottom: 16, justifyContent: 'space-between', width: '100%' }}>
				<Button icon={<ArrowLeftOutlined />} onClick={onBack}>
					Projects
				</Button>
				<Typography.Title level={4} style={{ margin: 0 }}>
					{project.name} — clients
				</Typography.Title>
				<Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
					New client
				</Button>
			</Space>
			<Table<ClientView>
				rowKey="clientId"
				loading={loading}
				dataSource={rows}
				columns={[
					{ title: 'Name', dataIndex: 'clientName' },
					{ title: 'Client ID', dataIndex: 'clientId' },
					{ title: 'Type', dataIndex: 'applicationType' },
					{ title: 'Auth', dataIndex: 'tokenEndpointAuthMethod' },
					{
						title: 'Grants',
						dataIndex: 'grantTypes',
						render: (g: string[]) => g.join(', ')
					},
					{
						title: 'Actions',
						render: (_: unknown, row: ClientView) => (
							<Space>
								<Button size="small" onClick={() => onRotate(row.clientId)}>
									Rotate secret
								</Button>
								<Popconfirm
									title="Delete this client?"
									onConfirm={() => onDelete(row.clientId)}
								>
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
				title="New client"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<FormValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
					initialValues={{
						applicationType: 'web',
						grantTypes: ['authorization_code'],
						tokenEndpointAuthMethod: 'none'
					}}
				>
					<Form.Item name="clientName" label="Name">
						<Input />
					</Form.Item>
					<Form.Item name="applicationType" label="Application type">
						<Select
							options={[
								{ label: 'web', value: 'web' },
								{ label: 'native', value: 'native' }
							]}
						/>
					</Form.Item>
					<Form.Item name="grantTypes" label="Grant types" rules={[{ required: true }]}>
						<Select mode="multiple" options={GRANT_OPTIONS} />
					</Form.Item>
					<Form.Item name="tokenEndpointAuthMethod" label="Token endpoint auth">
						<Select options={AUTH_OPTIONS} />
					</Form.Item>
					<Form.Item name="redirectUris" label="Redirect URIs (one per line)">
						<Input.TextArea rows={3} placeholder="https://app.example.com/cb" />
					</Form.Item>
					<Form.Item name="scope" label="Scope">
						<Input placeholder="openid profile email" />
					</Form.Item>
				</Form>
			</Modal>
			<Modal
				title="Client secret"
				open={secret !== null}
				onOk={() => setSecret(null)}
				onCancel={() => setSecret(null)}
				cancelButtonProps={{ style: { display: 'none' } }}
			>
				<Typography.Paragraph type="warning">
					Copy this secret now — it will not be shown again.
				</Typography.Paragraph>
				<Typography.Paragraph copyable code>
					{secret}
				</Typography.Paragraph>
			</Modal>
		</>
	);
}
```

- [ ] **Step 2: Wire the drill-down into Projects.tsx.** In `lib/admin/ui/pages/Projects.tsx`:

Add imports:
```tsx
import { Clients } from './Clients.js';
```
Add state inside `Projects()` (after the existing `useState` calls):
```tsx
	const [openProject, setOpenProject] = useState<Project | null>(null);
```
Right after `function Projects() {`'s return begins, short-circuit to the Clients view:
```tsx
	if (openProject) {
		return (
			<Clients project={openProject} onBack={() => setOpenProject(null)} />
		);
	}
```
Add a "Clients" action column to the table `columns` array:
```tsx
					{
						title: '',
						render: (_: unknown, row: Project) => (
							<Button size="small" onClick={() => setOpenProject(row)}>
								Clients
							</Button>
						)
					}
```
Add `Button` to the existing antd import if not already imported (it is).

- [ ] **Step 3: Build the bundle**

Run: `bun build.ts`
Expected: `built ./lib/admin/ui/adminClient.tsx → public/admin.js` with no errors.

- [ ] **Step 4: Typecheck the new UI**

Run: `bun run typecheck 2>&1 | grep -E "Clients.tsx|Projects.tsx" || echo "clean"`
Expected: `clean` (no new errors in these files).

- [ ] **Step 5: Commit**

```bash
git add lib/admin/ui/pages/Clients.tsx lib/admin/ui/pages/Projects.tsx public/admin.js
git commit -m "feat(admin): project clients drill-down UI"
```

(`public/admin.js` is a build artifact and normally untracked; include it only if the repo tracks built bundles — otherwise drop it from the `git add`.)

---

### Task 6: Full verification + browser e2e

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `bun test`
Expected: all pass, 0 fail (SP-1 counts + the new client_service/clients_routes/project_store/seed tests).

- [ ] **Step 2: Typecheck**

Run: `bun run typecheck 2>&1 | grep -E "admin/clients|Clients.tsx|projectStore|seed.ts" || echo "no new type errors in SP-2 files"`
Expected: `no new type errors in SP-2 files`.

- [ ] **Step 3: Browser e2e (real flow).** Start the server (`bun lib/index.ts`), log in to `/admin`, open a regular project → Clients → create an `authorization_code` + `none` client with a redirect URI. Verify: it appears in the list, the project's `clientIds` gained the id (check via mongo or a follow-up GET), and creating a `client_secret_basic` client surfaces the secret-once modal. Confirm the console is free of hydration/errors. Kill all `bun` processes afterward (`Get-Process bun | Stop-Process -Force`).

- [ ] **Step 4: Verify the created client actually works against the protocol.** For the public `authorization_code` client, hit `/auth?client_id=<newId>&response_type=code&redirect_uri=<uri>&scope=openid&code_challenge=...&code_challenge_method=S256` and confirm it reaches the login interaction (303) rather than an `invalid_client` error — proving admin-created clients are real protocol clients.

- [ ] **Step 5: Final commit (if any verification fixes were needed)**

```bash
git add -A
git commit -m "test(admin): verify SP-2 client management end-to-end"
```

---

## Self-Review

**Spec coverage:**
- `Project.clientIds` + stores → Task 1. ✓
- Admin project seeded `['admin-panel']` → Task 2. ✓
- CRUD + rotate API, RBAC, ownership scoping, admin-panel protection, secret-once, invariant → Tasks 3–4. ✓
- Curated editable fields + `validateClient` reuse → Task 3 (`toMetadata`). ✓
- All supported grant types → Task 3 `SUPPORTED_GRANT_TYPES` + Task 5 `GRANT_OPTIONS`. ✓
- Per-project drill-down UI + secret-once modal → Task 5. ✓
- Testing (store, routes, regression) → Tasks 1–4, 6. ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code. ✓

**Type consistency:** `AdminClientView`, `createClient`/`updateClient`/`rotateSecret`/`getClientView`/`deleteClientRecord` names match between Task 3 (definition), Task 4 (consumption), and tests. `Project.clientIds` used consistently. ✓

**Note for implementer:** `Client.validateClient` / `Client.needsSecret` / `Client.tryFind` / `Client.adapter` and `client.metadata()` are the real client-model surface (see `lib/actions/registration.ts` for the reference usage). If `toMetadata` produces a shape `validateClient` rejects, align it with registration's canonical/snake key split — never modify the client model to fit the admin layer.
