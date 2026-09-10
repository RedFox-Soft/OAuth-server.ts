import { describe, it, beforeAll, afterEach, expect, spyOn } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import * as adapters from 'lib/adapters/index.js';
import { resetReadinessCache } from 'lib/actions/ready.js';

/*
 * Liveness and readiness answer different questions, and this is the one part of the PostgreSQL work
 * with full integration coverage in the default run — its dependency is a `storagePing` that stubs
 * cleanly, so both states are reachable without a database.
 *
 * That matters beyond convenience. Everything else about a storage backend needs a real datastore to
 * observe, which is why the fidelity tier exists; readiness does not, so there is no excuse for it to
 * be covered only by hand.
 */

/**
 * @proves Readiness reports what storage can actually do, recovers on its own, never repeats the
 * driver error, and starts one probe per burst rather than one per caller.
 */
describe('liveness and readiness', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		// The endpoint caches its last answer for a second, so one case would otherwise decide the next.
		resetReadinessCache();
	});

	it('reports ready when storage answers', async () => {
		const { status, data } = await agent.ready.get();

		expect(status).toBe(200);
		expect(data).toEqual({ status: 'ready' });
	});

	it('reports not ready with 503 when storage does not answer', async () => {
		// 503 rather than 500: the server is working and its dependency is not, which is exactly the
		// distinction an orchestrator acts on — withdraw traffic, do not restart.
		const probe = spyOn(adapters, 'storagePing').mockRejectedValue(
			new Error('connection refused to db.internal:5432 as user oauth')
		);
		resetReadinessCache();

		const { status, error } = await agent.ready.get();

		expect(status).toBe(503);
		// Read from `error`, not `data`: Eden routes a non-2xx body there, and asserting on `data` would
		// compare against null and pass for the wrong reason.
		expect(error?.value).toEqual({
			status: 'not_ready',
			subsystem: 'storage'
		});
		probe.mockRestore();
	});

	it('never repeats the driver error, which carries the host', async () => {
		const probe = spyOn(adapters, 'storagePing').mockRejectedValue(
			new Error('connection refused to db.internal:5432 as user oauth')
		);
		resetReadinessCache();

		const { error } = await agent.ready.get();
		const body = JSON.stringify(error?.value);

		// Asserted against the real body for the same reason as above: `data` is null on a 503, so a
		// check against it would report success while proving nothing.
		expect(body).toContain('not_ready');
		expect(body).not.toContain('db.internal');
		expect(body).not.toContain('5432');
		probe.mockRestore();
	});

	it('recovers on its own once storage answers again', async () => {
		// Without this the endpoint would be a latch: an outage would take a restart to clear, which is
		// the opposite of what a readiness probe is for.
		const probe = spyOn(adapters, 'storagePing').mockRejectedValue(
			new Error('down')
		);
		resetReadinessCache();
		expect((await agent.ready.get()).status).toBe(503);

		probe.mockRestore();
		resetReadinessCache();
		expect((await agent.ready.get()).status).toBe(200);
	});

	it('keeps liveness answering from the process alone', async () => {
		// A failed liveness check means restart me; a failed readiness check means stop routing to me.
		// If a database outage tripped both, an orchestrator would restart a healthy process in a loop.
		const probe = spyOn(adapters, 'storagePing').mockRejectedValue(
			new Error('down')
		);
		resetReadinessCache();

		const { status } = await agent.health.get();

		expect(status).toBe(200);
		probe.mockRestore();
	});

	it('starts one probe, not one per caller, while an answer is outstanding', async () => {
		// Sharing the outstanding probe is what stops a readiness endpoint joining the outage it
		// reports: a database that has stopped answering leaves the probe outstanding for its whole
		// deadline, and without this every probe arriving in that window opens another query against a
		// database already failing to keep up.
		let release!: () => void;
		const outstanding = new Promise<void>((resolve) => {
			release = () => resolve();
		});
		const probe = spyOn(adapters, 'storagePing').mockReturnValue(outstanding);
		resetReadinessCache();

		const answers = Promise.all([
			agent.ready.get(),
			agent.ready.get(),
			agent.ready.get()
		]);
		// All three have to reach the endpoint before the answer arrives, or this proves nothing.
		await Bun.sleep(25);
		release();
		const settled = await answers;

		expect(probe.mock.calls.length).toBe(1);
		expect(settled.map((r) => r.status)).toEqual([200, 200, 200]);
		probe.mockRestore();
	});

	it('touches storage at most once per burst of probes', async () => {
		// An orchestrator polls on a fixed interval across several replicas. Without the hold, a rate
		// limit's worth of probes is a rate limit's worth of database round trips.
		const probe = spyOn(adapters, 'storagePing').mockResolvedValue(undefined);
		resetReadinessCache();

		await agent.ready.get();
		await agent.ready.get();
		await agent.ready.get();

		expect(probe.mock.calls.length).toBe(1);
		probe.mockRestore();
	});
});
