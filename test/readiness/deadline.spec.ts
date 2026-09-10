import { describe, it, expect } from 'bun:test';

import { withDeadline } from 'lib/helpers/deadline.js';

/*
 * The bound behind the readiness probe, tested where it costs milliseconds.
 *
 * It exists because of a measurement rather than a theory: against a paused PostgreSQL container —
 * a database that is up, connected and no longer answering — an unbounded probe took 30 seconds to
 * come back. A driver's connection timeout does not cover that case, because there is no connection
 * to establish. Both drivers behave the same way, so the bound sits at the seam they share.
 *
 * The second test is the one that would otherwise be forgotten: a race that leaves its loser's timer
 * armed keeps the process alive after the work it was guarding is done, which turns a probe into a
 * reason a container will not shut down.
 */

/**
 * @proves A readiness check that does not answer in time is rejected rather than hanging, real
 * errors pass through as themselves, and no timer is left behind.
 */
describe('withDeadline', () => {
	it('rejects when the work does not answer in time', async () => {
		const never = new Promise<string>(() => undefined);
		const started = Date.now();

		await expect(withDeadline(never, 25, 'storage')).rejects.toThrow(
			'storage did not answer within 25ms'
		);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	it('returns the work when it answers in time', async () => {
		await expect(
			withDeadline(Promise.resolve('answered'), 1000, 'storage')
		).resolves.toBe('answered');
	});

	it('passes a rejection through as itself, not as a timeout', async () => {
		// A refused connection and an unanswering database are different faults, and only one of them
		// is this function's doing. Reporting both as "did not answer" would hide the first.
		await expect(
			withDeadline(
				Promise.reject(new Error('connection refused')),
				1000,
				'storage'
			)
		).rejects.toThrow('connection refused');
	});

	it('leaves no timer behind when the work wins', async () => {
		const before = process.getActiveResourcesInfo?.().length ?? 0;

		await withDeadline(Promise.resolve(1), 30_000, 'storage');

		const after = process.getActiveResourcesInfo?.().length ?? 0;
		expect(after).toBeLessThanOrEqual(before);
	});
});
