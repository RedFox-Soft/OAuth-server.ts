import { afterEach, beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';

import bootstrap from '../test_helper.ts';
import { passOn, receiver } from './fixtures.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { telemetrySettingsRoutes } from 'lib/admin/settings/telemetry/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(telemetrySettingsRoutes);

/*
 * Read as raw JSON, not through the typed client: that client turns date-like strings into Date objects,
 * and the claim here is that the operator sees the report exactly as it was sent.
 */
async function statusAs(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	const response = await app.handle(
		new Request('http://localhost/admin/api/settings/telemetry', {
			headers: { cookie }
		})
	);
	return {
		status: response.status,
		data: response.ok
			? ((await response.json()) as Record<string, unknown>)
			: undefined
	};
}

/**
 * @proves A super administrator sees whether usage reporting is on and why not, the instance identifier,
 * when a report was last delivered, and byte for byte what was sent; nobody else sees it.
 */
describe('the usage reporting status', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	afterEach(() => {
		ApplicationConfig['telemetry.enabled'] = true;
	});

	it('shows the next report and no delivery before the first report', async () => {
		const { status, data } = await statusAs('super');

		expect(status).toBe(200);
		expect(data).toMatchObject({
			lastDeliveredAt: null,
			reportIsPreview: true,
			report: { format: 1 }
		});
	});

	it('shows exactly the report the receiver got', async () => {
		const sent = receiver();
		await passOn('2026-12-10T12:00:00Z');

		const { data } = await statusAs('super');

		expect(data).toMatchObject({
			reportIsPreview: false,
			lastDeliveredAt: '2026-12-10T12:00:00.000Z'
		});
		expect(data?.report).toEqual(sent.bodies[0]);
	});

	it('keeps the last delivery time after a report that was not delivered', async () => {
		receiver(503);
		await passOn('2026-12-11T12:00:00Z');

		const { data } = await statusAs('super');

		expect(data?.lastDeliveredAt).toBe('2026-12-10T12:00:00.000Z');
	});

	it('names the setting when it is turned off', async () => {
		ApplicationConfig['telemetry.enabled'] = false;

		const { data } = await statusAs('super');

		expect(data).toMatchObject({
			enabled: false,
			offBecause: 'setting',
			setting: false,
			nextReportAfter: null
		});
	});

	it('is refused to an administrator who is not a super administrator', async () => {
		const { status } = await statusAs('plain');

		expect(status).toBe(403);
	});
});
