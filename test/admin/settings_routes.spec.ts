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

	it('rejects PUT from an anonymous caller with 401', async () => {
		const res = await client.admin.api.settings.put({ 'par.enabled': true });
		expect(res.status).toBe(401);
	});

	it('forbids PUT from a project_admin with 403', async () => {
		const cookie = await sessionCookieFor(['project_admin']);
		const res = await client.admin.api.settings.put(
			{ 'par.enabled': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(403);
	});

	it('rejects an invalid deviceFlow.charset enum value with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'deviceFlow.charset': 'nope' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects an empty ciba.deliveryModes (merged-config invariant) with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'ciba.deliveryModes': [] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects an invalid deviceFlow.mask while deviceFlow is enabled with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'deviceFlow.enabled': true, 'deviceFlow.mask': '0000-0000' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('accepts a valid deviceFlow.mask while deviceFlow is enabled', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'deviceFlow.enabled': true, 'deviceFlow.mask': '****-****' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);
	});

	it('rejects jwtIntrospection enabled without introspection enabled with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'jwtIntrospection.enabled': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('accepts jwtIntrospection enabled together with introspection enabled', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'introspection.enabled': true, 'jwtIntrospection.enabled': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);
	});
});
