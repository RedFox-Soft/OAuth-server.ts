import { afterEach, beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { passOn, receiver } from './fixtures.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const client = treaty(new Elysia().use(resolveAdmin).use(settingsRoutes));

async function superAdminCookie(): Promise<string> {
	const user = await createAdministrator('super', `sa-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

function idOf(body: unknown): unknown {
	return (body as { instanceId?: unknown }).instanceId;
}

/**
 * @proves An operator stops every usage report with the console setting, without a restart, and it
 * resumes under the same identifier.
 */
describe('turning usage reporting off', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	afterEach(() => {
		ApplicationConfig['telemetry.enabled'] = true;
	});

	it('sends no report after a super administrator turns the setting off', async () => {
		const sent = receiver();
		const put = await client.admin.api.settings.put(
			{ 'telemetry.enabled': false },
			{ headers: { cookie: await superAdminCookie() } }
		);
		expect(put.status).toBe(200);

		await passOn('2026-11-20T12:00:00Z');

		expect(sent.requests).toBe(0);
	});

	it('reports under the identifier it had once turned back on', async () => {
		const sent = receiver();
		await passOn('2026-11-22T12:00:00Z');
		ApplicationConfig['telemetry.enabled'] = false;
		await passOn('2026-11-23T12:00:00Z');
		ApplicationConfig['telemetry.enabled'] = true;
		await passOn('2026-11-24T12:00:00Z');

		expect(sent.bodies).toHaveLength(2);
		expect(idOf(sent.bodies[1])).toBe(idOf(sent.bodies[0]));
	});
});
