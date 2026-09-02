import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';
import { initSentry, resetForTest as resetClient } from 'lib/sentry/client.ts';
import * as dispatch from 'lib/sentry/dispatch.ts';
import { clearRecorded, recordedEnvelopes } from 'lib/sentry/transport.ts';

/*
 * Monitoring cannot degrade the thing it monitors.
 *
 * Each case here is a way the outbound channel could become a second failure the caller sees: a dead
 * destination, a storm bigger than the queue, or a fault raised inside the reporting path itself. The
 * requirement is that none of them change a response, and that the local record survives all three —
 * the local record is the durable one, and reporting is only ever an addition to it.
 */
const previous = {
	store: ApplicationConfig['errorStore.enabled'],
	sentry: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

function appThrowing(route: string) {
	return new Elysia().onError(errorHandler).get(route, () => {
		throw new Error('deliberate fault');
	});
}

async function settle() {
	await flushForTest();
	await dispatch.flushForTest();
}

async function faultsOn(route: string) {
	const page = await errorStore.list({ route });
	return page.groups;
}

describe('sentry resilience', () => {
	beforeEach(() => {
		resetQueue();
		resetOriginSalt();
		dispatch.resetForTest();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = true;
		ApplicationConfig['sentry.enabled'] = true;
		ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';
		initSentry();
	});

	afterEach(() => {
		dispatch.resetForTest();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = previous.store;
		ApplicationConfig['sentry.enabled'] = previous.sentry;
		ApplicationConfig['sentry.dsn'] = previous.dsn;
	});

	/*
	 * The response is compared against the same request served with reporting off, rather than against
	 * a hand-written expectation: what matters is that arming the integration changes nothing, and only
	 * a comparison can say that.
	 */
	it('leaves the response identical to the reporting-disabled case', async () => {
		const armed = await appThrowing('/resil-same').handle(
			new Request('http://e.ly/resil-same')
		);
		const armedBody = (await armed.json()) as Record<string, unknown>;
		await settle();

		ApplicationConfig['sentry.enabled'] = false;
		resetClient();
		const bare = await appThrowing('/resil-same').handle(
			new Request('http://e.ly/resil-same')
		);
		const bareBody = (await bare.json()) as Record<string, unknown>;
		await settle();

		expect(armed.status).toBe(bare.status);
		expect([...armed.headers.keys()].sort()).toEqual(
			[...bare.headers.keys()].sort()
		);
		/* The reference differs by design — it is minted per fault — so compare the shape around it. */
		expect(Object.keys(armedBody).sort()).toEqual(Object.keys(bareBody).sort());
		expect(armedBody.error).toBe(bareBody.error);
	});

	it('answers and records every fault in a burst', async () => {
		const app = appThrowing('/resil-burst');
		for (let i = 0; i < 12; i += 1) {
			const response = await app.handle(new Request('http://e.ly/resil-burst'));
			expect(response.status).toBe(500);
		}
		await settle();

		/* Every fault is in the store, whatever the outbound channel managed to send. */
		const [group] = await faultsOn('/resil-burst');
		expect(group.occurrences).toBe(12);
	});

	/*
	 * The bound, exercised at the queue's own boundary rather than through the handler.
	 *
	 * Driving it through requests cannot saturate it: the drain is scheduled on a microtask and empties
	 * the queue completely, so an awaited request always lets it run before the next fault arrives —
	 * the queue is simply faster than a sequential caller. A real burst is many faults inside one tick,
	 * which is what this reproduces, and it is the only shape that reaches the bound deterministically.
	 */
	it('drops and counts beyond the dispatch bound', () => {
		const occurrence = {
			fingerprint: 'fp-burst',
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth' as const,
			route: '/resil-bound',
			method: 'GET',
			origin: { file: 'x.ts', line: 1, frame: 'f' },
			message: 'burst',
			record: {
				reference: 'err_AAAAAAAAAAAAAAAA',
				at: new Date(),
				clientId: null,
				actor: null,
				scope: null,
				requestId: null,
				origin: null,
				userAgent: null,
				submittedFields: []
			}
		};

		const overshoot = 8;
		for (let i = 0; i < dispatch.SENTRY_QUEUE_DEPTH + overshoot; i += 1) {
			dispatch.reportFault(occurrence);
		}

		expect(dispatch.droppedCount()).toBe(overshoot);
	});

	/*
	 * A fault raised inside reporting must not come back around. Without the guard this recurses:
	 * the throw reaches the handler, is classified as a new internal fault, and is reported again.
	 */
	it('does not recurse when reporting itself throws', async () => {
		const failing = spyOn(dispatch, 'reportFault').mockImplementation(() => {
			throw new Error('reporting exploded');
		});

		try {
			const response = await appThrowing('/resil-throw').handle(
				new Request('http://e.ly/resil-throw')
			);
			expect(response.status).toBe(500);
			await settle();

			/* The fault is recorded exactly once, not once per recursion. */
			const [group] = await faultsOn('/resil-throw');
			expect(group.occurrences).toBe(1);
		} finally {
			failing.mockRestore();
		}
	});

	it('reports nothing and answers normally when the client cannot be armed', async () => {
		ApplicationConfig['sentry.dsn'] = '';
		resetClient();

		const response = await appThrowing('/resil-unarmed').handle(
			new Request('http://e.ly/resil-unarmed')
		);
		expect(response.status).toBe(500);
		await settle();

		expect(recordedEnvelopes()).toHaveLength(0);
		expect(await faultsOn('/resil-unarmed')).toHaveLength(1);
	});

	/*
	 * A shutdown that hangs is worse than one that loses the tail: the events are lost either way and
	 * the second at least ends.
	 */
	it('bounds the shutdown drain rather than hanging', async () => {
		const app = appThrowing('/resil-drain');
		await app.handle(new Request('http://e.ly/resil-drain'));
		await flushForTest();

		const started = Date.now();
		await dispatch.drainForShutdown(50);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	it('never leaves a pending event behind after a drain', async () => {
		const app = appThrowing('/resil-empty');
		for (let i = 0; i < 3; i += 1) {
			await app.handle(new Request('http://e.ly/resil-empty'));
		}
		await settle();
		expect(dispatch.droppedCount()).toBe(0);
	});
});
