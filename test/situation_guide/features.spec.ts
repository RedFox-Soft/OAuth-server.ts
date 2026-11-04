import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import bootstrap from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { meRoutes } from 'lib/admin/me.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { applySettings } from 'lib/configs/application.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(meRoutes);
const client = treaty(app);

type Features = Record<string, boolean>;

/**
 * @proves the console and an agent read which guide features this instance has switched on, as it is now
 */
describe('the guide feature switches on /admin/api/me', () => {
	let superCookie: string;
	let plainCookie: string;

	async function featuresFor(cookie: string): Promise<Features> {
		const response = await client.admin.api.me.get({ headers: { cookie } });
		expect(response.status).toBe(200);
		return (response.data as unknown as { features: Features }).features;
	}

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'situation_guide' });
		await ensureAdminSeed();
		const sup = await createAdministrator('super', `f-${nanoid()}@x.io`);
		superCookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(sup))._id}`;
		const plain = await createAdministrator('plain', `p-${nanoid()}@x.io`);
		plainCookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(plain))._id}`;
	});

	it('reports the device flow off by default and on as soon as a saved setting turns it on', async () => {
		expect((await featuresFor(superCookie)).deviceFlow).toBe(false);
		expect(applySettings({ 'deviceFlow.enabled': true }).state).toBe('applied');
		expect((await featuresFor(superCookie)).deviceFlow).toBe(true);
	});

	it('gives an ordinary administrator the same switches', async () => {
		expect(await featuresFor(plainCookie)).toEqual(
			await featuresFor(superCookie)
		);
	});
});
