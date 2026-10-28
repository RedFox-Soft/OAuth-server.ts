import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { passOn, receiver } from './fixtures.ts';
import { resetStoresForTests } from 'lib/adapters/index.ts';
import { TelemetryStateStore } from 'lib/adapters/memory/telemetryStateStore.ts';
import { reportPass } from 'lib/telemetry/scheduler.ts';
import { sendReport } from 'lib/telemetry/send.ts';

function idOf(body: unknown): unknown {
	return (body as { instanceId?: unknown }).instanceId;
}

/**
 * @proves Reports from one server always carry its own identifier, two servers never share one, and a
 * server reports once a day however many processes it runs.
 */
describe('the instance identifier', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('stays the same when the server reports again after a restart', async () => {
		const sent = receiver();
		await passOn('2026-11-10T12:00:00Z');
		await passOn('2026-11-11T12:00:00Z');

		expect(sent.bodies).toHaveLength(2);
		expect(idOf(sent.bodies[1])).toBe(idOf(sent.bodies[0]));
	});

	it('differs between servers on separate databases', async () => {
		const first = new TelemetryStateStore();
		const second = new TelemetryStateStore();

		expect(await first.instanceId()).not.toBe(await second.instanceId());
	});

	it('is a random UUID rather than anything derived from the server', async () => {
		const sent = receiver();
		await passOn('2026-11-12T12:00:00Z');

		expect(String(idOf(sent.bodies[0]))).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
		);
	});

	it('gives one report a day to processes sharing a database', async () => {
		const sent = receiver();
		// Straight to the pass: three overlapping clock changes would not unwind to where they started.
		await Promise.all(
			['12:00', '12:05', '13:00'].map((time) =>
				reportPass(new Date(`2026-11-13T${time}:00Z`), sendReport, {
					ignoreSlot: true
				})
			)
		);

		expect(sent.requests).toBe(1);
	});

	it('is a new one for a new database', async () => {
		const sent = receiver();
		await passOn('2026-11-14T12:00:00Z');
		resetStoresForTests();
		await passOn('2026-11-15T12:00:00Z');

		expect(idOf(sent.bodies[1])).not.toBe(idOf(sent.bodies[0]));
	});
});
