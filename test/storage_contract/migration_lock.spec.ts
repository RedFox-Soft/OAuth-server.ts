import { describe, it, expect } from 'bun:test';

import {
	MigrationLockBusy,
	withLease,
	type LeaseStore
} from 'lib/migrations/lock.js';

/*
 * Mutual exclusion between migration runs — contract M3.5 to M3.7.
 *
 * The store below is the smallest thing that satisfies the interface, and the interesting behaviour
 * lives in `withLease` rather than in any datastore: whether a second run is refused, whether an
 * expired lease is takeable, and whether the lock is released when the work throws.
 */

function leaseStore(): LeaseStore & {
	held: { holder: string; expiresAt: Date } | null;
} {
	const state: { held: { holder: string; expiresAt: Date } | null } = {
		held: null
	};

	return {
		get held() {
			return state.held;
		},
		set held(value) {
			state.held = value;
		},
		async read() {
			return state.held;
		},
		async acquire(holder, expiresAt) {
			const current = state.held;
			const free =
				current === null ||
				current.holder === holder ||
				current.expiresAt.getTime() <= Date.now();
			if (!free) return false;
			state.held = { holder, expiresAt };
			return true;
		},
		async release(holder) {
			if (state.held?.holder === holder) state.held = null;
		}
	};
}

describe('withLease', () => {
	it('runs the work and releases afterwards', async () => {
		const store = leaseStore();
		const result = await withLease(store, 'run-1', async () => 'done');

		expect(result).toBe('done');
		expect(store.held).toBeNull();
	});

	it('holds the lease while the work runs', async () => {
		const store = leaseStore();
		await withLease(store, 'run-1', async () => {
			expect(store.held?.holder).toBe('run-1');
		});
	});

	it('refuses a second holder while a live lease stands', async () => {
		const store = leaseStore();
		store.held = { holder: 'run-1', expiresAt: new Date(Date.now() + 60_000) };

		await expect(
			withLease(store, 'run-2', async () => 'never')
		).rejects.toThrow(MigrationLockBusy);
	});

	it('names the holder and the expiry, so waiting is an informed decision', async () => {
		const store = leaseStore();
		const expiresAt = new Date(Date.now() + 60_000);
		store.held = { holder: 'run-1', expiresAt };

		await expect(withLease(store, 'run-2', async () => 0)).rejects.toThrow(
			/run-1/
		);
	});

	it('takes over a lease that has expired', async () => {
		// A crashed holder must not block every future run — the reason the lease exists at all rather
		// than a flag that is only ever cleared on the happy path.
		const store = leaseStore();
		store.held = { holder: 'dead-run', expiresAt: new Date(Date.now() - 1) };

		const result = await withLease(store, 'run-2', async () => 'taken over');

		expect(result).toBe('taken over');
		expect(store.held).toBeNull();
	});

	it('releases the lease when the work throws', async () => {
		// A failed migration must leave the lock free. Otherwise the fix — re-running after correcting
		// the cause — is blocked by the failure it is fixing.
		const store = leaseStore();

		await expect(
			withLease(store, 'run-1', async () => {
				throw new Error('deliberate');
			})
		).rejects.toThrow('deliberate');

		expect(store.held).toBeNull();
	});

	it('releases only its own lease', async () => {
		// A run that overran its lease must not free the lock a later run has legitimately taken.
		const store = leaseStore();
		await store.acquire('run-1', new Date(Date.now() + 60_000));
		await store.release('run-2');

		expect(store.held?.holder).toBe('run-1');
	});
});
