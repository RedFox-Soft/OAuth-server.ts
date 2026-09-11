import { describe, it, expect, beforeEach } from 'bun:test';

import { SingletonSecretStore } from 'lib/adapters/memory/singletonSecretStore.ts';

// The nonce-secret store contract — specs/014-dpop-nonce-safety/contracts/nonce-secret-store.md.
//
// Memory implementation only. lib/adapters/mongodb/db.ts opens its connection at module scope and
// throws without MONGODB_URI, which this suite deliberately lacks, so the MongoDB class cannot be
// imported here WITHOUT SUBSTITUTING THAT MODULE — which is the step this file's earlier note, and
// every sibling's, stopped short of. mongo_bson_round_trip.spec.ts does substitute it and runs the
// real class against the real BSON codec; the storage-encoding half is covered there, not by hand.
// What still needs a server, and is still out of reach here, is everything in Tier 2 of
// wiki/concepts/mongodb-test-fidelity.md.
//
// The load-bearing property under test is that create and replace return the value AS READ BACK
// rather than the candidate they were handed. That is what makes the round-trip check structural
// (a caller cannot accidentally trust an unpersisted value) and what gives a losing writer the
// winner's value from the very call that failed to take effect.
//
// "No implicit removal" is not tested here: it is a property of the storage inventory, where
// serviceConfig is declared `reaped: null`, and it is pinned by
// test/storage_contract/inventory_expiry.spec.ts. Asserting it against an in-memory map would prove
// nothing about the deployment.

const bytes = (fill: number): Buffer => Buffer.alloc(32, fill);

/**
 * @proves The nonce secret round-trips as bytes, is never overwritten on create, and two racing
 * replicas converge on one value.
 */
describe('SingletonSecretStore (memory): DPoP nonce secret instance', () => {
	let store: SingletonSecretStore;

	beforeEach(() => {
		store = new SingletonSecretStore('dpopNonceSecret');
	});

	it('reads nothing from an empty store', async () => {
		expect(await store.read()).toBeNull();
	});

	it('creates a record and reads back what it wrote', async () => {
		expect(await store.create(bytes(1))).toEqual(bytes(1));
		expect(await store.read()).toEqual(bytes(1));
	});

	it('never overwrites on create, and hands back the incumbent', async () => {
		await store.create(bytes(1));

		expect(await store.create(bytes(2))).toEqual(bytes(1));
		expect(await store.read()).toEqual(bytes(1));
	});

	it('converges when two creates race', async () => {
		const [first, second] = await Promise.all([
			store.create(bytes(1)),
			store.create(bytes(2))
		]);

		// Which candidate wins is deliberately unspecified; that both callers end up holding the one
		// stored value is not.
		expect(first).toEqual(second);
		expect(await store.read()).toEqual(first);
	});

	it('replaces when the observed value is still current', async () => {
		const observed = await store.create(bytes(1));

		expect(await store.replace(observed, bytes(2))).toEqual(bytes(2));
		expect(await store.read()).toEqual(bytes(2));
	});

	it('does not replace on a stale observed value, and hands back the incumbent', async () => {
		const stale = await store.create(bytes(1));
		await store.replace(stale, bytes(2));

		// A competing instance replaced the value first; this caller's write must not take effect, and
		// it must learn the winner's value from its own failed call.
		expect(await store.replace(stale, bytes(3))).toEqual(bytes(2));
		expect(await store.read()).toEqual(bytes(2));
	});

	it('replaces on an empty store without inventing a record', async () => {
		// Nothing observed, nothing stored: the filter cannot match, so the write must not take effect.
		expect(await store.replace(null, bytes(1))).toBeNull();
		expect(await store.read()).toBeNull();
	});
});
