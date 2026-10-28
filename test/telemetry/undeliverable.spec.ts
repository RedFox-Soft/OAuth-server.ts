import { beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { hangingReceiver, passOn, receiver } from './fixtures.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { errorRoutes } from 'lib/admin/errors/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { TELEMETRY_DESTINATION } from 'lib/consts/telemetry_fields.ts';
import { sendReport } from 'lib/telemetry/send.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const console_ = treaty(new Elysia().use(resolveAdmin).use(errorRoutes));

async function recordedFaults(): Promise<number> {
	const user = await createAdministrator('super', `sa-${Math.random()}@x.io`);
	const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	// Recording is a microtask behind the capture; let it land before reading.
	await new Promise((resolve) => setTimeout(resolve, 20));
	const { status, data } = await console_.admin.api.errors.get({
		headers: { cookie }
	});
	expect(status).toBe(200);
	return (data as { total: number }).total;
}

/**
 * @proves A usage report that cannot be delivered leaves no trace for the operator, is abandoned within
 * its bound, and is neither retried that day nor sent late.
 */
describe('a report that cannot be delivered', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	it('leaves no error-store record when the receiver refuses it', async () => {
		receiver(503);
		await passOn('2026-12-01T12:00:00Z');

		expect(await recordedFaults()).toBe(0);
	});

	it('is abandoned within its bound when the receiver never answers', async () => {
		hangingReceiver();
		const started = Date.now();
		await passOn('2026-12-02T12:00:00Z', (report) =>
			sendReport(report, TELEMETRY_DESTINATION, 50)
		);

		expect(Date.now() - started).toBeLessThan(2000);
	});

	it('is not attempted again the same day after it failed', async () => {
		const sent = receiver(503);
		await passOn('2026-12-03T09:00:00Z');
		await passOn('2026-12-03T18:00:00Z');

		expect(sent.requests).toBe(1);
	});

	it('is not sent late for the days the receiver was unreachable', async () => {
		const sent = receiver(503);
		await passOn('2026-12-04T12:00:00Z');
		sent.status = 204;
		await passOn('2026-12-08T12:00:00Z');

		expect(sent.requests).toBe(2);
		expect(sent.bodies.at(-1)).not.toHaveProperty('day.date', '2026-12-04');
	});
});
