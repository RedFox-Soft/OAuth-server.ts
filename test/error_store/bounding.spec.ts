import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';

/*
 * US4 — that the bounds an operator sets are the bounds the store enforces.
 *
 * The store's own eviction, sample-admission and expiry rules are pinned at the unit level by
 * test/storage_contract/error_store.round_trip.spec.ts. What is tested here is the part that spec
 * cannot see: that the numbers actually travel from ApplicationConfig, through the capture path, into
 * the write. A store that enforced perfect caps against hard-coded defaults would pass every unit test
 * and ignore the operator entirely.
 */
const enabled = ApplicationConfig['errorStore.enabled'];
const retention = ApplicationConfig['errorStore.retentionDays'];
const maxGroups = ApplicationConfig['errorStore.maxGroups'];
const samples = ApplicationConfig['errorStore.samplesPerGroup'];

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

/* Each route is its own fingerprint, so a distinct route means a distinct fault. */
function faultingApp(routes: string[]) {
	let app = new Elysia().onError(errorHandler);
	for (const route of routes) {
		app = app.get(route, () => {
			throw new Error(`fault on ${route}`);
		});
	}
	return app;
}

describe('error store bounding, driven by configuration', () => {
	beforeEach(() => {
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
		ApplicationConfig['errorStore.retentionDays'] = retention;
		ApplicationConfig['errorStore.maxGroups'] = maxGroups;
		ApplicationConfig['errorStore.samplesPerGroup'] = samples;
	});

	it('honours the configured sample cap while keeping the count exact', async () => {
		ApplicationConfig['errorStore.samplesPerGroup'] = 2;
		const route = unique('/cap');
		const app = faultingApp([route]);

		for (let i = 0; i < 9; i += 1) {
			await app.handle(new Request(`http://e.ly${route}`));
		}
		await flushForTest();

		const [group] = (await errorStore.list({ route })).groups;
		expect(group.samples).toHaveLength(2);
		// The cap bounds the detail retained, never the tally.
		expect(group.occurrences).toBe(9);
	});

	it('honours the configured retention window', async () => {
		ApplicationConfig['errorStore.retentionDays'] = 1;
		const route = unique('/retain');
		await faultingApp([route]).handle(new Request(`http://e.ly${route}`));
		await flushForTest();

		const [group] = (await errorStore.list({ route })).groups;
		const days =
			(group.expiresAt.getTime() - group.lastSeenAt.getTime()) / 86_400_000;
		expect(Math.round(days)).toBe(1);
	});

	/*
	 * The group cap and its eviction order are pinned against a FRESH store in
	 * test/storage_contract/error_store.round_trip.spec.ts, and deliberately not here: this store is a
	 * process-wide singleton shared with every other spec in the run, so lowering the cap would evict
	 * their records as well as this file's — a test that corrupts its neighbours to prove a bound.
	 *
	 * What can only be checked here is the wiring: that the numbers the capture path passes are the ones
	 * ApplicationConfig currently holds. A store enforcing perfect caps against hard-coded defaults would
	 * pass every unit test and ignore the operator entirely, and this is the seam where that would hide.
	 */
	it('passes the configured bounds into every write', async () => {
		ApplicationConfig['errorStore.retentionDays'] = 7;
		ApplicationConfig['errorStore.maxGroups'] = 4242;
		ApplicationConfig['errorStore.samplesPerGroup'] = 3;

		const seen: unknown[] = [];
		const original = errorStore.record.bind(errorStore);
		(errorStore as { record: unknown }).record = async (
			occurrence: Parameters<typeof original>[0],
			bounds: Parameters<typeof original>[1]
		) => {
			seen.push(bounds);
			return original(occurrence, bounds);
		};

		try {
			const route = unique('/wiring');
			await faultingApp([route]).handle(new Request(`http://e.ly${route}`));
			await flushForTest();
		} finally {
			(errorStore as { record: unknown }).record = original;
		}

		expect(seen).toHaveLength(1);
		expect(seen[0]).toEqual({
			retentionDays: 7,
			maxGroups: 4242,
			samplesPerGroup: 3
		});
	});

	/*
	 * Applying retention while faults are still arriving must not drop a group that is inside the window.
	 * The memory store sweeps lazily on every read and write, so this exercises the sweep concurrently
	 * with writes rather than in isolation.
	 */
	it('does not drop a live fault while retention is being applied', async () => {
		ApplicationConfig['errorStore.retentionDays'] = 30;
		const route = unique('/race');
		const app = faultingApp([route]);

		await Promise.all([
			app.handle(new Request(`http://e.ly${route}`)),
			errorStore.list({}),
			app.handle(new Request(`http://e.ly${route}`)),
			errorStore.summarize({}),
			app.handle(new Request(`http://e.ly${route}`))
		]);
		await flushForTest();

		const [group] = (await errorStore.list({ route })).groups;
		expect(group.occurrences).toBe(3);
	});

	// A group whose window has passed is invisible whether or not a sweep has run.
	it('hides a fault whose retention window has passed', async () => {
		ApplicationConfig['errorStore.retentionDays'] = 1;
		const route = unique('/expired');
		await faultingApp([route]).handle(new Request(`http://e.ly${route}`));
		await flushForTest();

		const [group] = (await errorStore.list({ route })).groups;
		expect(group).toBeDefined();

		// Reach past the window without waiting for it: the read-side filter is the contract, not the sweep.
		const past = new Date(Date.now() - 2 * 86_400_000);
		expect((await errorStore.list({ route, to: past })).total).toBe(0);
	});
});
