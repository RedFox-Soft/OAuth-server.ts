import { describe, it, expect, spyOn } from 'bun:test';

import {
	generatePairwiseSalt,
	isUsablePairwiseSalt,
	resolvePairwiseSalt
} from 'lib/configs/pairwiseSalt.ts';
import type { SecretStoreInstance } from 'lib/adapters/types.ts';
import { SingletonSecretStore } from 'lib/adapters/memory/singletonSecretStore.ts';

// The narrowing predicate and the generator —
// specs/023-pairwise-identifier-salt/data-model.md, "Validation rules".
//
// Same predicate reasoning as the DPoP nonce secret's, and for the same reason: the defect class is a
// value arriving in a shape the declared type calls impossible, so the check is a runtime predicate
// over `unknown` rather than a type assertion. What differs is the cost of getting it wrong. A nonce
// secret wrongly accepted throws on first use; a salt wrongly accepted silently derives identifiers
// nobody can reproduce.

describe('pairwise salt: usability predicate', () => {
	it('accepts exactly 32 bytes of buffer material', () => {
		expect(isUsablePairwiseSalt(Buffer.alloc(32, 0))).toBe(true);
		expect(isUsablePairwiseSalt(Buffer.alloc(32, 0xff))).toBe(true);
	});

	it('rejects a buffer of the wrong length', () => {
		expect(isUsablePairwiseSalt(Buffer.alloc(16, 0))).toBe(false);
		expect(isUsablePairwiseSalt(Buffer.alloc(33, 0))).toBe(false);
		expect(isUsablePairwiseSalt(Buffer.alloc(0))).toBe(false);
	});

	it('rejects the shapes a naive storage round trip produces', () => {
		// The task 35 failure class, in the two shapes it actually arrives in: a JSON round trip, and a
		// driver's binary wrapper. Both are 32 "bytes" by their own reckoning and neither is material.
		expect(
			isUsablePairwiseSalt({ type: 'Buffer', data: new Array(32).fill(0) })
		).toBe(false);
		expect(isUsablePairwiseSalt({ buffer: Buffer.alloc(32, 0) })).toBe(false);
	});

	it('accepts a plain Uint8Array, which is what a structured clone leaves behind', () => {
		// Deliberately not rejected: a cloned Buffer comes back a plain Uint8Array and hashes
		// identically. Rejecting it would fail a valid deployment to guard against nothing.
		expect(isUsablePairwiseSalt(new Uint8Array(32))).toBe(true);
		expect(isUsablePairwiseSalt(structuredClone(Buffer.alloc(32, 3)))).toBe(
			true
		);
		expect(isUsablePairwiseSalt(new Uint8Array(16))).toBe(false);
	});

	it('rejects absent and non-object values', () => {
		expect(isUsablePairwiseSalt(undefined)).toBe(false);
		expect(isUsablePairwiseSalt(null)).toBe(false);
		expect(isUsablePairwiseSalt('0'.repeat(32))).toBe(false);
		expect(isUsablePairwiseSalt(32)).toBe(false);
	});
});

describe('pairwise salt: generation', () => {
	it('generates usable material', () => {
		expect(isUsablePairwiseSalt(generatePairwiseSalt())).toBe(true);
	});

	it('does not generate the same value twice', () => {
		expect(generatePairwiseSalt().equals(generatePairwiseSalt())).toBe(false);
	});
});

/*
 * Startup resolution — spec 023, User Story 1 and 2.
 *
 * Driven through stub stores, because the interesting cases are the ones where storage misbehaves and
 * the in-memory adapter cannot misbehave. A stub returns the shape a real driver returns.
 */

// Counts writes, so a test can assert storage was NOT touched as well as that it was. The salt
// resolver must never call `replace` at all — see the contract — so that counter existing is itself
// part of what is under test.
class StubStore implements SecretStoreInstance {
	created = 0;
	replaced = 0;

	constructor(
		private stored: unknown = null,
		private readsBackAs: 'written' | 'mangled' = 'written'
	) {}

	async read(): Promise<unknown> {
		return this.stored;
	}

	async create(secret: Buffer): Promise<unknown> {
		this.created += 1;
		this.stored = this.readsBackAs === 'written' ? secret : mangled();
		return this.stored;
	}

	async replace(_observed: unknown, secret: Buffer): Promise<unknown> {
		this.replaced += 1;
		this.stored = this.readsBackAs === 'written' ? secret : mangled();
		return this.stored;
	}
}

const mangled = () => JSON.parse(JSON.stringify(Buffer.alloc(32, 1)));

const quiet = () => spyOn(console, 'warn').mockImplementation(() => {});

describe('pairwise salt: startup resolution', () => {
	it('provisions when storage holds nothing, and says nothing about it', async () => {
		const store = new StubStore(null);
		const warn = quiet();

		const salt = await resolvePairwiseSalt(store, undefined);

		expect(isUsablePairwiseSalt(salt)).toBe(true);
		expect(store.created).toBe(1);
		// First-boot provisioning is the ordinary path for every fresh deployment. Announcing it would
		// train an operator to ignore this channel, which is where the messages that matter go.
		expect(warn).not.toHaveBeenCalled();
		warn.mockRestore();
	});

	it('returns the identical salt on a second resolution, and writes nothing', async () => {
		// The two-boot proof. A real second process cannot see the first one's store under the
		// in-memory adapter, so boot-to-boot identity is proven here — against a store that persists
		// across the two calls, which is what a restart actually is.
		const store = new SingletonSecretStore('pairwiseSalt');

		const first = await resolvePairwiseSalt(store, undefined);
		const second = await resolvePairwiseSalt(store, undefined);

		expect(isUsablePairwiseSalt(first)).toBe(true);
		expect(Buffer.from(second as Uint8Array)).toEqual(
			Buffer.from(first as Uint8Array)
		);
	});

	it('refuses a stored value it cannot use, and leaves it exactly as found', async () => {
		// The clarified decision (spec Clarifications, 2026-08-23): fail closed rather than replace.
		// Replacing would reassign every relying party's account key, and the realistic cause of an
		// unusable value recurs on every boot — so it would do so on every restart, silently.
		const store = new StubStore(Buffer.alloc(16, 0));
		const warn = quiet();

		const salt = await resolvePairwiseSalt(store, undefined);

		expect(salt).toBeNull();
		expect(store.created).toBe(0);
		expect(store.replaced).toBe(0);
		expect(await store.read()).toEqual(Buffer.alloc(16, 0));
		expect(warn).toHaveBeenCalled();
		warn.mockRestore();
	});

	it('refuses a value the storage layer mangles on the way back, and does not trust its own candidate', async () => {
		// A freshly written salt read back unusable: the persistence layer cannot carry the value. The
		// candidate this process generated is durable nowhere, so using it would make every instance
		// disagree — the exact failure the round-trip check exists to catch.
		const store = new StubStore(null, 'mangled');
		const warn = quiet();

		const salt = await resolvePairwiseSalt(store, undefined);

		expect(salt).toBeNull();
		expect(store.created).toBe(1);
		expect(store.replaced).toBe(0);
		expect(warn).toHaveBeenCalled();
		warn.mockRestore();
	});

	it('converges when two resolutions race an empty store', async () => {
		const store = new SingletonSecretStore('pairwiseSalt');

		const [first, second] = await Promise.all([
			resolvePairwiseSalt(store, undefined),
			resolvePairwiseSalt(store, undefined)
		]);

		expect(isUsablePairwiseSalt(first)).toBe(true);
		expect(Buffer.from(second as Uint8Array)).toEqual(
			Buffer.from(first as Uint8Array)
		);
	});

	it('honours a usable in-process value verbatim and never touches storage', async () => {
		// What makes a fixed salt in a test meaningful: it wins outright, so a spec can compute the
		// identifier it expects.
		const store = new StubStore(Buffer.alloc(32, 9));
		const configured = Buffer.alloc(32, 4);

		const salt = await resolvePairwiseSalt(store, configured);

		expect(salt).toBe(configured);
		expect(store.created).toBe(0);
		expect(store.replaced).toBe(0);
	});

	it('ignores an unusable in-process value loudly rather than fatally', async () => {
		// Loud, not fatal: the administrative plane is served by this same process, so a server that
		// will not start cannot be repaired through any supported surface.
		const store = new StubStore(null);
		const warn = quiet();

		const salt = await resolvePairwiseSalt(store, Buffer.alloc(8, 0));

		expect(isUsablePairwiseSalt(salt)).toBe(true);
		expect(store.created).toBe(1);
		expect(warn).toHaveBeenCalled();
		warn.mockRestore();
	});

	it('never calls replace, on any path', async () => {
		// The interface carries `replace` for the nonce secret, which repairs an unusable value. The
		// salt has no repair path by design, so the operation must be unreachable from this resolver.
		const cases = [
			new StubStore(null),
			new StubStore(Buffer.alloc(16, 0)),
			new StubStore(Buffer.alloc(32, 5)),
			new StubStore(null, 'mangled')
		];
		const warn = quiet();

		for (const store of cases) {
			await resolvePairwiseSalt(store, undefined);
			expect(store.replaced).toBe(0);
		}

		warn.mockRestore();
	});
});
