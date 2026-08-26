import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import {
	drainForShutdown,
	droppedCount,
	flushForTest,
	resetQueue
} from 'lib/error_store/queue.ts';

/*
 * The write path's durability contract (FR-007, FR-007a, FR-007b, SC-007).
 *
 * Recording cannot be awaited on the request path — a store failure must not become a second failure
 * the caller sees — so what is durable is stated rather than absolute: nothing is lost on a graceful
 * shutdown, and an abrupt kill loses at most the queue depth. What must never happen is a loss that is
 * unbounded, or silent.
 */
const enabled = ApplicationConfig['errorStore.enabled'];
const depth = ApplicationConfig['errorStore.queueDepth'];

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

function faulting(route: string) {
	return new Elysia().onError(errorHandler).get(route, () => {
		throw new Error('durability fault');
	});
}

describe('error store durability', () => {
	beforeEach(() => {
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
		ApplicationConfig['errorStore.queueDepth'] = depth;
		resetQueue();
	});

	it('writes queued records when the process drains on shutdown', async () => {
		const route = unique('/drain');
		const app = faulting(route);

		await app.handle(new Request(`http://e.ly${route}`));
		await drainForShutdown();

		expect((await errorStore.list({ route })).total).toBe(1);
	});

	// Bounded in time, because a store that has stopped answering must not hold the process open. Losing
	// the tail is bad; never exiting is worse, and the records are lost either way.
	it('gives up draining rather than hanging on a store that never answers', async () => {
		const original = errorStore.record;
		(errorStore as { record: unknown }).record = () =>
			new Promise(() => {
				/* never settles */
			});

		try {
			const route = unique('/drain-hang');
			await faulting(route).handle(new Request(`http://e.ly${route}`));

			const started = Date.now();
			await drainForShutdown(50);
			expect(Date.now() - started).toBeLessThan(2000);
		} finally {
			(errorStore as { record: unknown }).record = original;
		}
	});

	/*
	 * Overflow is counted, not silent and not blocking. A store that looks complete while missing faults
	 * is the failure with the longest gap between cause and discovery — an operator reads an empty list
	 * and concludes the server is healthy.
	 */
	it('counts what it cannot queue, and still answers every request', async () => {
		ApplicationConfig['errorStore.queueDepth'] = 2;

		// The store never settles, so the queue cannot drain and fills.
		const original = errorStore.record;
		(errorStore as { record: unknown }).record = () =>
			new Promise(() => {
				/* never settles */
			});

		try {
			const route = unique('/overflow');
			const app = faulting(route);

			const statuses: number[] = [];
			for (let i = 0; i < 12; i += 1) {
				const response = await app.handle(new Request(`http://e.ly${route}`));
				statuses.push(response.status);
			}

			// Every request answered normally: recording degraded, request handling did not.
			expect(statuses.every((status) => status === 500)).toBe(true);
			expect(droppedCount()).toBeGreaterThan(0);
		} finally {
			(errorStore as { record: unknown }).record = original;
		}
	});

	it('starts with nothing dropped', () => {
		expect(droppedCount()).toBe(0);
	});

	// FR-006 restated at the queue level: a rejecting store costs zero requests.
	it('fails no request when the store rejects every write', async () => {
		const original = errorStore.record;
		(errorStore as { record: unknown }).record = async () => {
			throw new Error('store rejects writes');
		};

		try {
			const route = unique('/reject');
			const app = faulting(route);

			for (let i = 0; i < 3; i += 1) {
				const response = await app.handle(new Request(`http://e.ly${route}`));
				expect(response.status).toBe(500);
			}
			await flushForTest();
		} finally {
			(errorStore as { record: unknown }).record = original;
		}
	});
});
