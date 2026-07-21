# Admin Panel SP-4 — Server-Settings Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A super_admin-only editor over a curated safe subset of `ApplicationConfig`, persisted through `configStore`, with persist-then-restart-to-apply semantics and a "restart required" banner.

**Architecture:** A single `catalog.ts` module lists every editable key with type/group/label/description — the source of truth for the server-side whitelist + validation and for UI rendering. `GET /admin/api/settings` returns the catalog plus the desired values (defaults ⊕ persisted) and a drift-based `restartRequired`/`changedKeys` computed against the live (boot-time) `ApplicationConfig`. `PUT` validates against the catalog, merges into the stored config, and calls `configStore.set` — it never mutates the running `ApplicationConfig`. The Settings stub becomes a real grouped form.

**Tech Stack:** Bun, Elysia, TypeBox, MongoDB + memory adapters, React 19 + Ant Design 6, bun:test + Eden treaty.

## Global Constraints

- Super_admin only: `GET`/`PUT /admin/api/settings` guarded by `resolveAdmin` + `assertAuth` + `assertRole('super_admin')`; errors in the SP-1 `admin_error` shape (`{ error, message }`).
- Persist + restart to apply: `PUT` writes to `configStore` and MUST NOT mutate the live `ApplicationConfig`. `restartRequired` = any editable key whose desired value differs from the running `ApplicationConfig` value.
- Editable set is exactly the catalog (curated safe subset). Reject any submitted key not in the catalog → 422. Enforce each descriptor's type; enum/option-constrained values must be members of the declared set → 422.
- Invariant: `scopes` must include `'openid'` → 422 otherwise.
- Do NOT expose or accept structured/function/Buffer keys (`claims`, `registration.policies`, `registration.initialAccessToken`, `richAuthorizationRequests.types`/`.ack`, `dpop.nonceSecret`).
- No change to the OIDC protocol surface or to `lib/configs/application.ts` / the `configStore` adapters.
- Follow SP-1..SP-3 patterns: `new Elysia({ name }).use(resolveAdmin).onError(...)`, `assertAuth(admin as AdminContext | null)`, memory adapter in tests. TDD, DRY, YAGNI, one commit per task. Tests run with `bun test`.

---

### Task 1: Settings catalog + PUT body schema

**Files:**
- Create: `lib/admin/settings/catalog.ts`
- Create: `lib/admin/settings/schema.ts`
- Test: `test/admin/settings_catalog.spec.ts`

**Interfaces:**
- Produces:
  - `SettingType = 'boolean' | 'string' | 'enum' | 'string-array'`
  - `interface SettingDescriptor { key: keyof typeof ApplicationConfig; group: string; label: string; description: string; type: SettingType; options?: string[] }`
  - `SETTINGS_CATALOG: SettingDescriptor[]` (the ordered editable-key list)
  - `UpdateSettingsBody` (TypeBox) — a record of arbitrary string keys → unknown values.
- Consumes: `ApplicationConfig` from `lib/configs/application.js` (for the `key` type only).

- [ ] **Step 1: Write the failing test.** Create `test/admin/settings_catalog.spec.ts`:

```ts
import { describe, it, expect } from 'bun:test';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

describe('settings catalog', () => {
	it('every catalog key exists in ApplicationConfig', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(Object.prototype.hasOwnProperty.call(ApplicationConfig, d.key)).toBe(
				true
			);
		}
	});

	it('descriptors are well-formed and keys are unique', () => {
		const seen = new Set<string>();
		for (const d of SETTINGS_CATALOG) {
			expect(seen.has(d.key)).toBe(false);
			seen.add(d.key);
			expect(d.group.length).toBeGreaterThan(0);
			expect(d.label.length).toBeGreaterThan(0);
			expect(['boolean', 'string', 'enum', 'string-array']).toContain(d.type);
			if (d.type === 'enum') expect(Array.isArray(d.options)).toBe(true);
		}
	});

	it('excludes structured/function/Buffer keys', () => {
		const keys = SETTINGS_CATALOG.map((d) => d.key);
		for (const forbidden of [
			'claims',
			'registration.policies',
			'registration.initialAccessToken',
			'richAuthorizationRequests.types',
			'richAuthorizationRequests.ack',
			'dpop.nonceSecret'
		]) {
			expect(keys).not.toContain(forbidden);
		}
	});

	it('declared enum/option values match the ApplicationConfig defaults domain', () => {
		const charset = SETTINGS_CATALOG.find((d) => d.key === 'deviceFlow.charset');
		expect(charset?.options).toEqual(['base-20', 'digits']);
		const delivery = SETTINGS_CATALOG.find((d) => d.key === 'ciba.deliveryModes');
		expect(delivery?.options).toEqual(['poll', 'ping']);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/settings_catalog.spec.ts`
Expected: FAIL (`lib/admin/settings/catalog.ts` does not exist).

- [ ] **Step 3: Implement the catalog.** Create `lib/admin/settings/catalog.ts`:

```ts
import { ApplicationConfig } from '../../configs/application.js';

export type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';

export interface SettingDescriptor {
	key: keyof typeof ApplicationConfig;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
}

const CLIENT_AUTH_METHODS = [
	'client_secret_basic',
	'client_secret_jwt',
	'client_secret_post',
	'private_key_jwt',
	'none'
];

// Single source of truth for the editable settings: drives the API whitelist,
// server-side validation, and the UI form. Descriptions are condensed from the
// doc-comments in lib/configs/application.ts.
export const SETTINGS_CATALOG: SettingDescriptor[] = [
	{ key: 'par.enabled', group: 'PAR', label: 'Enable PAR (RFC 9126)', type: 'boolean', description: 'Enables the pushed_authorization_request endpoint.' },
	{ key: 'par.allowUnregisteredRedirectUris', group: 'PAR', label: 'Allow unregistered redirect_uris via PAR', type: 'boolean', description: 'Lets authenticated PAR clients use unregistered redirect_uri values (no sector_identifier_uri).' },

	{ key: 'dpop.enabled', group: 'DPoP', label: 'Enable DPoP (RFC 9449)', type: 'boolean', description: 'Sender-constrains tokens via application-layer proof-of-possession.' },
	{ key: 'dpop.requireNonce', group: 'DPoP', label: 'Require DPoP nonce', type: 'boolean', description: 'Requires a server-provided DPoP nonce.' },
	{ key: 'dpop.allowReplay', group: 'DPoP', label: 'Allow DPoP proof replay', type: 'boolean', description: 'Disables DPoP proof replay detection.' },

	{ key: 'introspection.enabled', group: 'Introspection', label: 'Enable Token Introspection (RFC 7662)', type: 'boolean', description: 'Enables introspection for opaque access tokens and refresh tokens.' },
	{ key: 'jwtIntrospection.enabled', group: 'Introspection', label: 'JWT introspection responses (RFC 9701)', type: 'boolean', description: 'JWT responses for introspection. Requires Introspection enabled.' },

	{ key: 'responseMode.jwt.enabled', group: 'JWT Response Modes', label: 'Enable JARM', type: 'boolean', description: 'Enables JWT Secured Authorization Responses.' },

	{ key: 'fapi.enabled', group: 'FAPI', label: 'Enable FAPI behaviours', type: 'boolean', description: 'Extra Authorization Server behaviours defined in the FAPI profile.' },

	{ key: 'clientCredentials.enabled', group: 'Client Credentials', label: 'Enable client_credentials grant', type: 'boolean', description: 'Enables grant_type=client_credentials on the token endpoint.' },

	{ key: 'devInteractions.enabled', group: 'Development', label: 'Enable dev interaction views', type: 'boolean', description: 'Development-only out-of-the-box interaction views. Disable in production.' },

	{ key: 'backchannelLogout.enabled', group: 'Back-Channel Logout', label: 'Enable Back-Channel Logout', type: 'boolean', description: 'Enables OIDC Back-Channel Logout features.' },

	{ key: 'encryption.enabled', group: 'Encryption', label: 'Enable encryption features', type: 'boolean', description: 'Encrypted UserInfo/ID Tokens and signed/encrypted Request Objects.' },

	{ key: 'userinfo.enabled', group: 'UserInfo', label: 'Enable the UserInfo endpoint', type: 'boolean', description: 'Enables the UserInfo endpoint.' },
	{ key: 'jwtUserinfo.enabled', group: 'UserInfo', label: 'JWT UserInfo responses', type: 'boolean', description: 'JWT responses for UserInfo. Requires UserInfo enabled.' },

	{ key: 'revocation.enabled', group: 'Revocation', label: 'Enable Token Revocation (RFC 7009)', type: 'boolean', description: 'Enables Token Revocation.' },

	{ key: 'rpInitiatedLogout.enabled', group: 'RP-Initiated Logout', label: 'Enable RP-Initiated Logout', type: 'boolean', description: 'Enables OIDC RP-Initiated Logout.' },

	{ key: 'claimsParameter.enabled', group: 'Claims Parameter', label: 'Enable the claims parameter', type: 'boolean', description: 'Enables use and validation of the claims parameter.' },

	{ key: 'mTLS.enabled', group: 'mTLS', label: 'Enable mTLS features (RFC 8705)', type: 'boolean', description: 'Enables Mutual TLS client authentication / certificate-bound tokens.' },
	{ key: 'mTLS.certificateBoundAccessTokens', group: 'mTLS', label: 'Certificate-bound access tokens', type: 'boolean', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.selfSignedTlsClientAuth', group: 'mTLS', label: 'self_signed_tls_client_auth method', type: 'boolean', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.tlsClientAuth', group: 'mTLS', label: 'tls_client_auth method', type: 'boolean', description: 'Requires mTLS enabled.' },

	{ key: 'deviceFlow.enabled', group: 'Device Flow', label: 'Enable Device Authorization Grant (RFC 8628)', type: 'boolean', description: 'Enables the Device Authorization Grant.' },
	{ key: 'deviceFlow.charset', group: 'Device Flow', label: 'User-code charset', type: 'enum', options: ['base-20', 'digits'], description: 'Character set for generated user codes.' },
	{ key: 'deviceFlow.mask', group: 'Device Flow', label: 'User-code mask', type: 'string', description: 'Template for user codes; * is replaced by a random charset char.' },

	{ key: 'ciba.enabled', group: 'CIBA', label: 'Enable CIBA flow', type: 'boolean', description: 'Enables Core CIBA flow.' },
	{ key: 'ciba.deliveryModes', group: 'CIBA', label: 'Token delivery modes', type: 'string-array', options: ['poll', 'ping'], description: 'Supported CIBA token delivery modes.' },

	{ key: 'requestObjects.enabled', group: 'Request Objects', label: 'Enable Request Objects (JAR)', type: 'boolean', description: 'Enables the request (Request Object) parameter.' },
	{ key: 'requestObjects.requireSignedRequestObject', group: 'Request Objects', label: 'Require signed request objects', type: 'boolean', description: 'Requires signed request objects for all authorization requests.' },

	{ key: 'resourceIndicators.enabled', group: 'Resource Indicators', label: 'Enable Resource Indicators (RFC 8707)', type: 'boolean', description: 'Enables Resource Indicators features.' },

	{ key: 'richAuthorizationRequests.enabled', group: 'Rich Authorization Requests', label: 'Enable RAR (RFC 9396)', type: 'boolean', description: 'Enables the authorization_details parameter.' },

	{ key: 'registration.enabled', group: 'Registration', label: 'Enable Dynamic Client Registration', type: 'boolean', description: 'Enables Dynamic Client Registration.' },
	{ key: 'registration.issueRegistrationAccessToken', group: 'Registration', label: 'Issue registration access token', type: 'boolean', description: 'Whether a registration access token is issued.' },

	{ key: 'registrationManagement.enabled', group: 'Registration Management', label: 'Enable registration management (RFC 7592)', type: 'boolean', description: 'Enables update/delete for dynamically registered clients.' },
	{ key: 'registrationManagement.rotateRegistrationAccessToken', group: 'Registration Management', label: 'Rotate registration access token', type: 'boolean', description: 'Enables registration access token rotation.' },

	{ key: 'scopes', group: 'Discovery', label: 'Supported scopes', type: 'string-array', description: 'Scopes advertised in discovery. Must include openid.' },
	{ key: 'acrValues', group: 'Discovery', label: 'Supported acr values', type: 'string-array', description: 'ACR values the server supports (acr_values_supported).' },
	{ key: 'clientAuthMethods', group: 'Discovery', label: 'Client authentication methods', type: 'string-array', options: CLIENT_AUTH_METHODS, description: 'token_endpoint_auth_methods_supported (mTLS methods added when enabled).' }
];
```

- [ ] **Step 4: Implement the schema.** Create `lib/admin/settings/schema.ts`:

```ts
import { t } from 'elysia';

// A partial map of catalog key -> value. Per-field validation against the catalog
// (types, option membership, invariants) happens in the route handler so failures
// return the admin_error shape rather than a generic TypeBox validation error.
export const UpdateSettingsBody = t.Record(t.String(), t.Unknown());
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/settings_catalog.spec.ts`
Expected: PASS (4 tests). If a catalog `key` fails the `keyof typeof ApplicationConfig` type constraint, the key is misspelled — fix it against `lib/configs/application.ts`.

- [ ] **Step 6: Commit**

```bash
git add lib/admin/settings/catalog.ts lib/admin/settings/schema.ts test/admin/settings_catalog.spec.ts
git commit -m "feat(admin): settings catalog + PUT body schema"
```

---

### Task 2: Settings routes (GET/PUT) + wire into adminApp

**Files:**
- Create: `lib/admin/settings/routes.ts`
- Modify: `lib/admin/index.ts` (add `.use(settingsRoutes)`)
- Test: `test/admin/settings_routes.spec.ts`

**Interfaces:**
- Consumes: `SETTINGS_CATALOG`, `SettingDescriptor` from `./catalog.js`; `UpdateSettingsBody` from `./schema.js`; `ApplicationConfig` from `lib/configs/application.js`; `configStore` from `lib/adapters/index.js`; `resolveAdmin`, `assertAuth`, `assertRole`, `AdminError`, `AdminContext` from `../auth/rbac.js`.
- Produces: `settingsRoutes` (Elysia plugin). Response shape for both routes: `{ catalog: SettingDescriptor[]; values: Record<string, unknown>; restartRequired: boolean; changedKeys: string[] }`.

- [ ] **Step 1: Write the failing test.** Create `test/admin/settings_routes.spec.ts`:

```ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { adminSessionStore, getUserStore, configStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(settingsRoutes);
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
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

interface SettingsResponse {
	catalog: Array<{ key: string; type: string }>;
	values: Record<string, unknown>;
	restartRequired: boolean;
	changedKeys: string[];
}

describe('settings API', () => {
	beforeEach(async () => {
		await configStore.set({}); // no persisted overrides -> desired == running
	});

	it('rejects anonymous access', async () => {
		const res = await client.admin.api.settings.get();
		expect(res.status).toBe(401);
	});

	it('forbids a project_admin', async () => {
		const cookie = await sessionCookieFor(['project_admin']);
		const res = await client.admin.api.settings.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});

	it('GET returns the catalog with no restart required when nothing is persisted', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.get({ headers: { cookie } });
		expect(res.status).toBe(200);
		const body = res.data as SettingsResponse;
		expect(body.catalog.length).toBeGreaterThan(0);
		expect(body.restartRequired).toBe(false);
		expect(body.changedKeys).toEqual([]);
		expect(Object.prototype.hasOwnProperty.call(body.values, 'par.enabled')).toBe(true);
	});

	it('PUT persists a change and reports restartRequired + changedKeys', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const before = (await client.admin.api.settings.get({ headers: { cookie } }))
			.data as SettingsResponse;
		const running = before.values['par.enabled'] as boolean;
		const put = await client.admin.api.settings.put(
			{ 'par.enabled': !running },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(200);
		const body = put.data as SettingsResponse;
		expect(body.values['par.enabled']).toBe(!running);
		expect(body.restartRequired).toBe(true);
		expect(body.changedKeys).toContain('par.enabled');
		// round-trips via configStore
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['par.enabled']).toBe(!running);
	});

	it('preserves unedited stored overrides across a second PUT', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		await client.admin.api.settings.put({ 'par.enabled': true }, { headers: { cookie } });
		await client.admin.api.settings.put({ 'revocation.enabled': true }, { headers: { cookie } });
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['par.enabled']).toBe(true);
		expect(stored['revocation.enabled']).toBe(true);
	});

	it('rejects an unknown key with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'not.a.real.setting': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects a wrong-typed value with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'par.enabled': 'yes' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects a string-array element outside the option set with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'ciba.deliveryModes': ['poll', 'carrier-pigeon'] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects scopes without openid with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ scopes: ['offline_access'] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/settings_routes.spec.ts`
Expected: FAIL (`lib/admin/settings/routes.ts` does not exist).

- [ ] **Step 3: Implement the routes.** Create `lib/admin/settings/routes.ts`:

```ts
import { Elysia } from 'elysia';
import { ApplicationConfig } from '../../configs/application.js';
import { configStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { SETTINGS_CATALOG, type SettingDescriptor } from './catalog.js';
import { UpdateSettingsBody } from './schema.js';

const CATALOG_BY_KEY = new Map<string, SettingDescriptor>(
	SETTINGS_CATALOG.map((d) => [d.key as string, d])
);

const running = (key: string): unknown =>
	(ApplicationConfig as Record<string, unknown>)[key];

const sameValue = (a: unknown, b: unknown): boolean =>
	JSON.stringify(a) === JSON.stringify(b);

// Validate one submitted value against its descriptor. Throws AdminError(422) on any
// type/option/invariant violation.
function validateValue(descriptor: SettingDescriptor, value: unknown): void {
	const { key, type, options } = descriptor;
	if (type === 'boolean') {
		if (typeof value !== 'boolean')
			throw new AdminError(422, `${key} must be a boolean`);
	} else if (type === 'string') {
		if (typeof value !== 'string')
			throw new AdminError(422, `${key} must be a string`);
	} else if (type === 'enum') {
		if (typeof value !== 'string' || !options?.includes(value))
			throw new AdminError(422, `${key} must be one of: ${options?.join(', ')}`);
	} else {
		// string-array
		if (!Array.isArray(value) || !value.every((v) => typeof v === 'string'))
			throw new AdminError(422, `${key} must be an array of strings`);
		if (options && !value.every((v) => options.includes(v as string)))
			throw new AdminError(422, `${key} values must be among: ${options.join(', ')}`);
		if (key === 'scopes' && !value.includes('openid'))
			throw new AdminError(422, 'scopes must include "openid"');
	}
}

async function currentState() {
	const stored = (await configStore.get()) ?? {};
	const values: Record<string, unknown> = {};
	const changedKeys: string[] = [];
	for (const d of SETTINGS_CATALOG) {
		const run = running(d.key as string);
		const desired = Object.prototype.hasOwnProperty.call(stored, d.key as string)
			? (stored as Record<string, unknown>)[d.key as string]
			: run;
		values[d.key as string] = desired;
		if (!sameValue(desired, run)) changedKeys.push(d.key as string);
	}
	return {
		catalog: SETTINGS_CATALOG,
		values,
		restartRequired: changedKeys.length > 0,
		changedKeys
	};
}

export const settingsRoutes = new Elysia({ name: 'admin-settings' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/settings', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return currentState();
	})
	.put(
		'/admin/api/settings',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			for (const [key, value] of Object.entries(body)) {
				const descriptor = CATALOG_BY_KEY.get(key);
				if (!descriptor) throw new AdminError(422, `unknown setting: ${key}`);
				validateValue(descriptor, value);
			}
			const stored = (await configStore.get()) ?? {};
			await configStore.set({ ...stored, ...body });
			return currentState();
		},
		{ body: UpdateSettingsBody }
	);
```

- [ ] **Step 4: Wire into adminApp.** In `lib/admin/index.ts`:

Add the import near the other route imports:
```ts
import { settingsRoutes } from './settings/routes.js';
```
Add to the chain after `.use(endUserRoutes)`:
```ts
	.use(settingsRoutes)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/admin/settings_routes.spec.ts`
Expected: PASS (9 tests).

- [ ] **Step 6: Commit**

```bash
git add lib/admin/settings/routes.ts lib/admin/index.ts test/admin/settings_routes.spec.ts
git commit -m "feat(admin): server-settings GET/PUT routes (super_admin)"
```

---

### Task 3: UI — Settings editor page

**Files:**
- Create: `lib/admin/ui/pages/Settings.tsx`
- Modify: `lib/admin/ui/pages/Layout.tsx` (render `<Settings/>` for the `settings` page)
- Build: `bun build.ts`

**Interfaces:**
- Consumes: `GET`/`PUT /admin/api/settings` (Task 2).
- Produces: `Settings` React component `Settings()` (no props).

- [ ] **Step 1: Implement the Settings page.** Create `lib/admin/ui/pages/Settings.tsx`:

```tsx
import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Form,
	Input,
	Select,
	Switch,
	Typography,
	message
} from 'antd';

type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';
interface Descriptor {
	key: string;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
}
interface SettingsResponse {
	catalog: Descriptor[];
	values: Record<string, unknown>;
	restartRequired: boolean;
	changedKeys: string[];
}

export function Settings() {
	const [catalog, setCatalog] = useState<Descriptor[]>([]);
	const [values, setValues] = useState<Record<string, unknown>>({});
	const [restartRequired, setRestartRequired] = useState(false);
	const [changedKeys, setChangedKeys] = useState<string[]>([]);
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);

	function apply(body: SettingsResponse) {
		setCatalog(body.catalog);
		setValues(body.values);
		setRestartRequired(body.restartRequired);
		setChangedKeys(body.changedKeys);
	}

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/settings');
			if (res.ok) apply((await res.json()) as SettingsResponse);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function save() {
		setSaving(true);
		try {
			const res = await fetch('/admin/api/settings', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			const body = (await res.json().catch(() => null)) as
				| (SettingsResponse & { message?: string })
				| null;
			if (!res.ok) {
				message.error(body?.message || 'failed to save settings');
				return;
			}
			if (body) apply(body);
			message.success('settings saved');
		} finally {
			setSaving(false);
		}
	}

	const groups = useMemo(() => {
		const map = new Map<string, Descriptor[]>();
		for (const d of catalog) {
			if (!map.has(d.group)) map.set(d.group, []);
			map.get(d.group)!.push(d);
		}
		return [...map.entries()];
	}, [catalog]);

	function setValue(key: string, value: unknown) {
		setValues((prev) => ({ ...prev, [key]: value }));
	}

	function control(d: Descriptor) {
		const value = values[d.key];
		if (d.type === 'boolean') {
			return (
				<Switch
					checked={value === true}
					onChange={(checked) => setValue(d.key, checked)}
				/>
			);
		}
		if (d.type === 'enum') {
			return (
				<Select
					style={{ minWidth: 220 }}
					value={value as string}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		if (d.type === 'string-array') {
			return (
				<Select
					mode={d.options ? 'multiple' : 'tags'}
					style={{ minWidth: 320 }}
					value={(value as string[]) ?? []}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		return (
			<Input
				style={{ maxWidth: 320 }}
				value={(value as string) ?? ''}
				onChange={(e) => setValue(d.key, e.target.value)}
			/>
		);
	}

	return (
		<>
			<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
				<Typography.Title level={4} style={{ margin: 0 }}>
					Server settings
				</Typography.Title>
				<Button type="primary" loading={saving} onClick={save}>
					Save
				</Button>
			</div>
			{restartRequired && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Restart required to apply"
					description={`Saved changes take effect after a server restart: ${changedKeys.join(', ')}`}
				/>
			)}
			{groups.map(([group, items]) => (
				<Card key={group} title={group} size="small" style={{ marginBottom: 16 }} loading={loading}>
					<Form layout="vertical">
						{items.map((d) => (
							<Form.Item
								key={d.key}
								label={d.label}
								help={d.description}
								style={{ marginBottom: 16 }}
							>
								{control(d)}
							</Form.Item>
						))}
					</Form>
				</Card>
			))}
		</>
	);
}
```

- [ ] **Step 2: Render it in the Layout.** In `lib/admin/ui/pages/Layout.tsx`:

Add the import:
```tsx
import { Settings } from './Settings.js';
```
In `renderPage()`, replace the `settings` case:
```tsx
			case 'settings':
				return isSuperAdmin ? <Settings /> : <Projects isSuperAdmin={isSuperAdmin} />;
```
(Leave the `keys` case as `<Stub title="Keys" />` — that is SP-5.)

- [ ] **Step 3: Build the bundle**

Run: `bun build.ts`
Expected: `built ./lib/admin/ui/adminClient.tsx → public/admin.js` with no errors.

- [ ] **Step 4: Typecheck the new/changed UI**

Run: `bun run typecheck 2>&1 | grep -E "Settings\.tsx|Layout\.tsx" || echo "clean"`
Expected: `clean`.

- [ ] **Step 5: Commit**

```bash
git add lib/admin/ui/pages/Settings.tsx lib/admin/ui/pages/Layout.tsx
git commit -m "feat(admin): server-settings editor UI"
```
(`public/admin.js` is a build artifact and is not tracked in this repo — do not add it. Confirm with `git ls-files public/admin.js` returning nothing.)

---

### Task 4: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `bun test`
Expected: all pass, 0 fail (prior counts + `settings_catalog` 4 + `settings_routes` 9). If a lone cross-suite flake appears, re-run the failing file in isolation before treating it as a real failure.

- [ ] **Step 2: Typecheck**

Run: `bun run typecheck 2>&1 | grep -E "admin/settings|Settings\.tsx|catalog\.ts" || echo "no new type errors in SP-4 files"`
Expected: `no new type errors in SP-4 files`.

- [ ] **Step 3: Server smoke test.** Start the server (`bun lib/index.ts`), then without a session confirm auth is enforced:

Run: `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/admin/api/settings`
Expected: `401`.

Confirm the bundle serves: `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/public/admin.js` → `200`. Kill the server afterward (`Get-Process bun | Stop-Process -Force`).

- [ ] **Step 4: Authenticated UI check (manual — needs admin credentials).** Log in to `/admin` as super_admin, open **Settings**: confirm grouped sections render with toggles/inputs, change a flag (e.g. enable Revocation), Save → the "restart required to apply" banner appears listing the changed key, and reloading the page shows the saved value persisted. Confirm a project_admin does not see the Settings nav item. (This step is not automatable here without credentials; flag results to the reviewer.)

- [ ] **Step 5: Final commit (if any verification fixes were needed)**

```bash
git add -A
git commit -m "test(admin): verify SP-4 server-settings editor end-to-end"
```

---

## Self-Review

**Spec coverage:**
- Catalog module (SSOT for whitelist/validation/UI) → Task 1. ✓
- Persist + restart-to-apply, drift-based `restartRequired`/`changedKeys`, no live mutation → Task 2 (`currentState`, `configStore.set` only). ✓
- Curated editable subset; excluded structured/function/Buffer keys → Task 1 catalog + Task 1 test. ✓
- Validation (unknown key, type, option membership, openid guard) → Task 2 `validateValue` + tests. ✓
- Super_admin-only API; `admin_error` shape → Task 2 (`assertRole`, `.onError`) + RBAC tests. ✓
- GET/PUT API shape `{ catalog, values, restartRequired, changedKeys }` → Task 2. ✓
- UI grouped form + restart banner, replaces stub, super-only → Task 3. ✓
- Testing (catalog, validation, GET/PUT persist + drift, RBAC) → Tasks 1–2, 4. ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code. ✓

**Type consistency:** `SettingDescriptor`/`SETTINGS_CATALOG`/`UpdateSettingsBody` defined in Task 1 and consumed in Task 2; response shape `{ catalog, values, restartRequired, changedKeys }` consistent across Task 2 routes, Task 2 tests, and Task 3 UI. `settingsRoutes` name matches between Task 2 definition and the Task 2 mount. ✓

**Note for implementer:** `ApplicationConfig` is the live boot-time snapshot (never mutated by these routes) — `running(key)` reads it directly; `desired` comes from `configStore`. The tests reset `configStore.set({})` in `beforeEach` so `desired == running` initially (`restartRequired: false`), and drive drift by toggling a value relative to the value GET returns, so they never hardcode a running default.
