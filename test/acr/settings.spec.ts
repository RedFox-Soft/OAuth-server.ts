import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { getUserStore, configStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor as adminSessionFor } from '../admin_session.ts';
import {
	ApplicationConfig,
	configuration,
	reloadConfiguration
} from 'lib/configs/application.js';
import { DEFAULT_ACR_VALUES } from 'lib/consts/acr.ts';

const app = new Elysia().use(resolveAdmin).use(settingsRoutes);
const client = treaty(app);

async function superAdminCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`acr-admin-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await adminSessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

// What the settings document holds; fails the case when there is none.
async function storedSettings() {
	const stored = await configStore.get();
	if (!stored) throw new Error('expected a settings document');
	return stored;
}

function put(cookie: string, acrValues: unknown) {
	return client.admin.api.settings.put({ acrValues }, { headers: { cookie } });
}

const named = {
	password: 'bronze',
	multi_factor: 'silver',
	federated: 'gold'
};

/**
 * @proves An administrator can name the authentication contexts their relying parties expect, and
 * is refused with a reason when the names would make the server describe itself untruthfully.
 */
describe('naming the authentication contexts', () => {
	let cookie: string;

	beforeEach(async () => {
		cookie = await superAdminCookie();
		await configStore.set({});
		Object.assign(ApplicationConfig, { acrValues: { ...DEFAULT_ACR_VALUES } });
		reloadConfiguration();
	});

	it('accepts a value for every authentication the server can distinguish', async () => {
		const { response } = await put(cookie, named);

		expect(response.status).toBe(200);
		expect((await storedSettings()).acrValues).toEqual(named);
	});

	it('reports the renamed values as in force, with nothing waiting', async () => {
		const { data } = await put(cookie, named);
		if (!data || 'error' in data) throw new Error('expected the settings');

		expect(data.appliedKeys).toContain('acrValues');
		expect(data.pendingRestartKeys).toEqual([]);
		expect(data.notInForceKeys).toEqual([]);
	});

	it('advertises the renamed values from the next request, without a restart', async () => {
		await put(cookie, named);

		expect([...configuration.acrValues]).toEqual(['bronze', 'silver', 'gold']);
		expect(configuration.claimsSupported).toContain('acr');
	});

	it('refuses a value shared by two authentications, naming the clash', async () => {
		const { response, error } = await put(cookie, {
			...named,
			multi_factor: 'bronze'
		});

		expect(response.status).toBe(422);
		expect(JSON.stringify(error?.value)).toContain(
			'repeats the value given to password'
		);
	});

	it('refuses the value reserved for an authentication carrying no confidence', async () => {
		const { response, error } = await put(cookie, { ...named, password: '0' });

		expect(response.status).toBe(422);
		expect(JSON.stringify(error?.value)).toContain("may not be '0'");
	});

	it('refuses an authentication the server cannot distinguish', async () => {
		const { response, error } = await put(cookie, {
			...named,
			retina_scan: 'platinum'
		});

		expect(response.status).toBe(422);
		expect(JSON.stringify(error?.value)).toContain("names 'retina_scan'");
	});

	it('refuses a list, which cannot say which authentication a value describes', async () => {
		const { response } = await put(cookie, ['bronze', 'silver']);

		expect(response.status).toBe(422);
	});

	it('leaves the settings unchanged when it refuses', async () => {
		await put(cookie, { ...named, password: '0' });

		expect((await storedSettings()).acrValues).toBeUndefined();
	});
});
