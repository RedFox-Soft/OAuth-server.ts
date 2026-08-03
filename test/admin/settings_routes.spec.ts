import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore,
	configStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(settingsRoutes);
const client = treaty(app);

async function sessionFor(roles: string[]) {
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

async function sessionCookieFor(roles: string[]) {
	return (await sessionFor(roles)).cookie;
}

const SETTINGS_TARGET = 'ApplicationConfig';

// The audit log is append-only, so assertions measure the delta around one request
// rather than an absolute count.
const settingsAudit = () =>
	adminAuditStore.list({ targetType: SETTINGS_TARGET });

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
		expect(
			Object.prototype.hasOwnProperty.call(body.values, 'par.enabled')
		).toBe(true);
	});

	it('PUT persists a change and reports restartRequired + changedKeys', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const before = (
			await client.admin.api.settings.get({ headers: { cookie } })
		).data as SettingsResponse;
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
		await client.admin.api.settings.put(
			{ 'par.enabled': true },
			{ headers: { cookie } }
		);
		await client.admin.api.settings.put(
			{ 'revocation.enabled': true },
			{ headers: { cookie } }
		);
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['par.enabled']).toBe(true);
		expect(stored['revocation.enabled']).toBe(true);
	});

	it('persists authorization.allowOmittingSingleRegisteredRedirectUri (boolean) and round-trips', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const put = await client.admin.api.settings.put(
			{ 'authorization.allowOmittingSingleRegisteredRedirectUri': true },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(200);
		const body = put.data as SettingsResponse;
		expect(
			body.values['authorization.allowOmittingSingleRegisteredRedirectUri']
		).toBe(true);
		expect(body.restartRequired).toBe(true);
		expect(body.changedKeys).toContain(
			'authorization.allowOmittingSingleRegisteredRedirectUri'
		);
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(
			stored['authorization.allowOmittingSingleRegisteredRedirectUri']
		).toBe(true);
	});

	it('rejects a non-boolean authorization.allowOmittingSingleRegisteredRedirectUri with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ 'authorization.allowOmittingSingleRegisteredRedirectUri': 'yes' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	/*
	 * The RAR type map: the catalog's first structured (`json`) setting, and the reason the feature was
	 * previously unconfigurable — the key used to be function-valued, so no catalog entry could carry it.
	 * The rules here are not restated by the route: validateEffectiveConfig delegates to
	 * validateConfiguration, so these are the same rules that gate a boot (see
	 * test/configuration/rar_types.spec.ts).
	 */
	describe('richAuthorizationRequests.types (json setting)', () => {
		const types = {
			'https://scheme.example/payment': {
				label: 'Initiate a payment',
				fields: { actions: { required: true, allowed: ['initiate'] } }
			}
		};

		it('persists a descriptor map and round-trips it unchanged', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			const put = await client.admin.api.settings.put(
				{
					'richAuthorizationRequests.enabled': true,
					'richAuthorizationRequests.types': types
				},
				{ headers: { cookie } }
			);

			expect(put.status).toBe(200);
			const body = put.data as SettingsResponse;
			expect(body.values['richAuthorizationRequests.types']).toEqual(types);
			const stored = (await configStore.get()) as Record<string, unknown>;
			expect(stored['richAuthorizationRequests.types']).toEqual(types);
		});

		it('refuses enabling the feature with no types, leaving storage untouched', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			const before = await configStore.get();

			const res = await client.admin.api.settings.put(
				{
					'richAuthorizationRequests.enabled': true,
					'richAuthorizationRequests.types': {}
				},
				{ headers: { cookie } }
			);

			expect(res.status).toBe(422);
			expect(await configStore.get()).toEqual(before);
		});

		it('refuses a malformed descriptor, leaving storage untouched', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			const before = await configStore.get();

			for (const bad of [
				{ 'urn:t': {} },
				{ 'urn:t': { label: 'T', fields: { nope: {} } } },
				{ 'urn:t': { label: 'T', allowUnknownFields: 'yes' } }
			]) {
				const res = await client.admin.api.settings.put(
					{
						'richAuthorizationRequests.enabled': true,
						'richAuthorizationRequests.types': bad
					},
					{ headers: { cookie } }
				);
				expect(res.status).toBe(422);
			}

			expect(await configStore.get()).toEqual(before);
		});

		it('refuses a value that is not a JSON object at all', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			for (const bad of [[], 'nope', 5]) {
				const res = await client.admin.api.settings.put(
					{ 'richAuthorizationRequests.types': bad },
					{ headers: { cookie } }
				);
				expect(res.status).toBe(422);
			}
		});

		/*
		 * FR-004: judged on the resulting configuration as a whole. A batch that arms the feature next to
		 * an unrunnable companion is refused whole, so the valid half is not half-applied.
		 */
		it('refuses the whole batch when one setting makes it unrunnable', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			const before = await configStore.get();

			const res = await client.admin.api.settings.put(
				{
					'par.enabled': true,
					'richAuthorizationRequests.enabled': true,
					'richAuthorizationRequests.types': {}
				},
				{ headers: { cookie } }
			);

			expect(res.status).toBe(422);
			expect(await configStore.get()).toEqual(before);
		});
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

	// `discovery` is the distinctive case: unlike a nonexistent key, it DOES exist on
	// ApplicationConfig — it is relocated there but deliberately given no descriptor, so the
	// catalog gate is the only thing keeping it out of the admin surface.
	it('never exposes the relocated-but-unlisted discovery key', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.get({ headers: { cookie } });
		expect(res.status).toBe(200);
		const body = res.data as SettingsResponse;
		expect(body.catalog.map((d) => d.key)).not.toContain('discovery');
		expect(Object.prototype.hasOwnProperty.call(body.values, 'discovery')).toBe(
			false
		);
		expect(body.changedKeys).not.toContain('discovery');
	});

	it('rejects a PUT of the relocated-but-unlisted discovery key with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{
				discovery: { op_tos_uri: 'https://evil.example.com' }
			} as unknown as Record<string, boolean>,
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(Object.prototype.hasOwnProperty.call(stored, 'discovery')).toBe(
			false
		);
	});

	it('persists nothing when a batch mixes a valid setting with discovery', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{
				'revocation.enabled': true,
				discovery: { op_tos_uri: 'https://evil.example.com' }
			} as unknown as Record<string, boolean>,
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
		// Atomic rejection: validation runs over every key before configStore.set().
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(Object.prototype.hasOwnProperty.call(stored, 'discovery')).toBe(
			false
		);
		expect(
			Object.prototype.hasOwnProperty.call(stored, 'revocation.enabled')
		).toBe(false);
	});

	it('persists conformIdTokenClaims (boolean) and round-trips', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const put = await client.admin.api.settings.put(
			{ conformIdTokenClaims: false },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(200);
		const body = put.data as SettingsResponse;
		expect(body.values.conformIdTokenClaims).toBe(false);
		expect(body.restartRequired).toBe(true);
		expect(body.changedKeys).toContain('conformIdTokenClaims');
		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored.conformIdTokenClaims).toBe(false);
	});

	it('rejects a non-boolean conformIdTokenClaims with 422', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.settings.put(
			{ conformIdTokenClaims: 'nope' } as unknown as Record<string, boolean>,
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('audits a successful PUT with the acting admin and the changed keys', async () => {
		const { cookie, userId } = await sessionFor(['super_admin']);
		const before = (await settingsAudit()).length;
		const res = await client.admin.api.settings.put(
			{ 'revocation.enabled': true, 'par.enabled': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);

		const entries = await settingsAudit();
		expect(entries.length).toBe(before + 1);
		const entry = entries[entries.length - 1];
		expect(entry.action).toBe('settings.update');
		expect(entry.actorId).toBe(userId);
		expect(entry.actorEmail).toBeTruthy();
		// The entry schema has no metadata field, so the changed keys are the targetId.
		expect(entry.targetId).toBe('par.enabled,revocation.enabled');
	});

	it('writes no audit entry when a PUT is rejected', async () => {
		const cookie = await sessionCookieFor(['super_admin']);
		const before = (await settingsAudit()).length;
		const res = await client.admin.api.settings.put(
			{ 'par.enabled': 'nope' } as unknown as Record<string, boolean>,
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
		expect((await settingsAudit()).length).toBe(before);
	});

	/*
	 * The defect this feature was filed against, from the surface it was reachable from.
	 *
	 * Before spec 014, arming dpop.requireNonce was accepted and persisted with no nonce secret in
	 * place, and after the restart that applied it every DPoP-bearing request answered 500. It is
	 * accepted now for the opposite reason: the server provisions its own secret at startup, so the
	 * prerequisite is already met and there is nothing left for an operator to get wrong.
	 */
	describe('DPoP nonce enforcement', () => {
		it('accepts arming nonce enforcement, because the server holds its own secret', async () => {
			const cookie = await sessionCookieFor(['super_admin']);

			const res = await client.admin.api.settings.put(
				{ 'dpop.enabled': true, 'dpop.requireNonce': true },
				{ headers: { cookie } }
			);

			expect(res.status).toBe(200);
			// Boot-only like every setting: persisted now, live after a restart.
			expect((res.data as SettingsResponse).restartRequired).toBe(true);
			expect((res.data as SettingsResponse).changedKeys).toContain(
				'dpop.requireNonce'
			);
		});

		it('refuses to accept the nonce secret as a setting', async () => {
			const cookie = await sessionCookieFor(['super_admin']);

			// Server-owned state, not an operator override. The catalog is the allow-list, and the
			// secret is deliberately absent from it, so this is rejected as an unknown key rather than
			// validated and stored.
			const res = await client.admin.api.settings.put(
				{ 'dpop.nonceSecret': Buffer.alloc(32, 0) } as unknown as Record<
					string,
					boolean
				>,
				{ headers: { cookie } }
			);

			expect(res.status).toBe(422);
		});

		it('never discloses the nonce secret through the settings surface', async () => {
			const cookie = await sessionCookieFor(['super_admin']);

			const res = await client.admin.api.settings.get({ headers: { cookie } });

			expect(res.status).toBe(200);
			const body = res.data as SettingsResponse;
			expect(Object.keys(body.values)).not.toContain('dpop.nonceSecret');
			expect(body.catalog.map((d) => d.key)).not.toContain('dpop.nonceSecret');
			// Not merely absent from the keys: the value must not appear anywhere in the payload, in
			// any encoding a serializer might have chosen for a Buffer.
			expect(JSON.stringify(body)).not.toContain('nonceSecret');
		});

		it('refuses a batch whose merged result would not run, without partially applying it', async () => {
			const cookie = await sessionCookieFor(['super_admin']);
			const before = await configStore.get();

			// jwtIntrospection without introspection is one of the invariants the boot validator
			// enforces; pairing it with a valid DPoP change proves the whole batch is judged on its
			// merged result rather than key by key.
			const res = await client.admin.api.settings.put(
				{ 'dpop.requireNonce': true, 'jwtIntrospection.enabled': true },
				{ headers: { cookie } }
			);

			expect(res.status).toBe(422);
			expect(await configStore.get()).toEqual(before);
		});
	});
});
