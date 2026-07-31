import { describe, it, expect, spyOn } from 'bun:test';

import {
	generateNonceSecret,
	isUsableNonceSecret,
	resolveNonceSecret
} from 'lib/configs/nonceSecret.ts';
import type { DPoPNonceSecretStoreInstance } from 'lib/adapters/types.ts';
import { DPoPNonceSecretStore } from 'lib/adapters/memory/dpopNonceSecretStore.ts';
import { DPoPNonces } from 'lib/helpers/dpop_nonces.ts';

// The narrowing predicate and the generator — specs/014-dpop-nonce-safety/data-model.md.
//
// The predicate is the whole defence. The defect class this feature closes is a value arriving in a
// shape the declared type calls impossible, so the check has to be a runtime predicate over unknown
// rather than a type assertion; these cases are what make that claim checkable.

describe('nonce secret: usability predicate', () => {
	it('accepts exactly 32 bytes of buffer material', () => {
		expect(isUsableNonceSecret(Buffer.alloc(32, 0))).toBe(true);
		expect(isUsableNonceSecret(Buffer.alloc(32, 0xff))).toBe(true);
	});

	it('rejects a buffer of the wrong length', () => {
		expect(isUsableNonceSecret(Buffer.alloc(16, 0))).toBe(false);
		expect(isUsableNonceSecret(Buffer.alloc(33, 0))).toBe(false);
		expect(isUsableNonceSecret(Buffer.alloc(0))).toBe(false);
	});

	it('rejects the shapes a naive storage round trip produces', () => {
		// The case the feature exists for: a buffer written to a document store and read back as a
		// plain object, or as a driver's binary wrapper, is not byte material any more. Both are 32
		// "bytes" long by their own reckoning and neither can derive a nonce.
		expect(
			isUsableNonceSecret({ type: 'Buffer', data: new Array(32).fill(0) })
		).toBe(false);
		expect(isUsableNonceSecret({ buffer: Buffer.alloc(32, 0) })).toBe(false);
	});

	it('accepts a plain Uint8Array, which is what a structured clone leaves behind', () => {
		// Deliberately not rejected. A Buffer cloned along with the configuration comes back as a plain
		// Uint8Array, and it derives nonces perfectly well — hkdf takes any byte array. Rejecting it
		// would fail a valid deployment to guard against nothing, which is this bug's own mistake
		// pointed the other way. Found by the pre-existing "does not mutate the configuration it
		// validates" case in configuration.spec.ts, which clones ApplicationConfig.
		expect(isUsableNonceSecret(new Uint8Array(32))).toBe(true);
		expect(isUsableNonceSecret(structuredClone(Buffer.alloc(32, 3)))).toBe(
			true
		);
		expect(isUsableNonceSecret(new Uint8Array(16))).toBe(false);
	});

	it('rejects absent and non-object values', () => {
		expect(isUsableNonceSecret(undefined)).toBe(false);
		expect(isUsableNonceSecret(null)).toBe(false);
		expect(isUsableNonceSecret('0'.repeat(32))).toBe(false);
		expect(isUsableNonceSecret(32)).toBe(false);
	});
});

describe('nonce secret: generation', () => {
	it('generates usable material', () => {
		expect(isUsableNonceSecret(generateNonceSecret())).toBe(true);
	});

	it('does not generate the same value twice', () => {
		// A weak but sufficient signal that the source is a random one rather than a constant or a
		// counter. Entropy quality itself is the platform's guarantee, not something a test can assert.
		expect(generateNonceSecret().equals(generateNonceSecret())).toBe(false);
	});
});

/*
 * Startup resolution — spec 014, User Story 2.
 *
 * Driven through stub stores rather than a datastore, deliberately: the interesting cases are what
 * happens when storage misbehaves, and the in-memory adapter cannot misbehave. A stub can return the
 * shape a real driver returns, which is the failure the feature exists to survive.
 */

// Records what it was asked to do, so a test can assert storage was NOT touched as well as that it was.
class StubStore implements DPoPNonceSecretStoreInstance {
	created = 0;
	replaced = 0;

	constructor(
		private stored: unknown = null,
		/* What a write reads back as. Defaults to honest storage; set to simulate a broken round trip. */
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

// A 32-byte buffer that has been through a JSON round trip: the exact shape a document store hands
// back, and the one that used to reach the nonce generator's constructor and throw.
const mangled = () => JSON.parse(JSON.stringify(Buffer.alloc(32, 1)));

const quiet = () => spyOn(console, 'warn').mockImplementation(() => {});

describe('nonce secret: startup resolution', () => {
	it('provisions when storage holds nothing, and says nothing about it', async () => {
		const store = new StubStore(null);
		const warn = quiet();

		const secret = await resolveNonceSecret(store, undefined);

		expect(isUsableNonceSecret(secret)).toBe(true);
		expect(store.created).toBe(1);
		// Silent: this is the ordinary path for every fresh deployment, and a line printed on every
		// first boot is a line an operator learns to skip past.
		expect(warn).not.toHaveBeenCalled();
		warn.mockRestore();
	});

	it('reuses a usable stored secret verbatim and writes nothing', async () => {
		const stored = generateNonceSecret();
		const store = new StubStore(stored);

		const secret = await resolveNonceSecret(store, undefined);

		// Verbatim matters: a secret that changed on restart would invalidate every outstanding nonce.
		expect(secret).toBe(stored);
		expect(store.created).toBe(0);
		expect(store.replaced).toBe(0);
	});

	it('replaces an unusable stored secret, and says so without disclosing anything', async () => {
		const store = new StubStore(mangled());
		const warn = quiet();

		const secret = await resolveNonceSecret(store, undefined);

		expect(isUsableNonceSecret(secret)).toBe(true);
		expect(store.replaced).toBe(1);
		expect(store.created).toBe(0);

		expect(warn).toHaveBeenCalledTimes(1);
		const said = warn.mock.calls.flat().join(' ');
		expect(said).toMatch(/replaced the stored DPoP nonce secret/);
		// Never the value, in any encoding: the message explains the event and stops there.
		expect(said).not.toContain(Buffer.from(secret).toString('base64'));
		expect(said).not.toContain(Buffer.from(secret).toString('hex'));
		warn.mockRestore();
	});

	it('fails startup when a freshly written secret reads back unusable', async () => {
		// Storage that cannot carry binary values. Without this check the server would replace the
		// secret on every single boot, nonces would silently never survive a restart, and the
		// deployment would report healthy throughout — so this is loud and fatal instead.
		const store = new StubStore(null, 'mangled');
		const warn = quiet();

		await expect(resolveNonceSecret(store, undefined)).rejects.toThrow(
			/storage round trip/
		);
		warn.mockRestore();
	});

	it('names the storage layer rather than a setting when the round trip is broken', async () => {
		const store = new StubStore(mangled(), 'mangled');
		const warn = quiet();

		// An operator reading this must not go looking for a misconfigured setting: nothing they can
		// change will fix a persistence layer that mangles what it is given.
		await expect(resolveNonceSecret(store, undefined)).rejects.toThrow(
			/storage layer cannot carry binary values/
		);
		warn.mockRestore();
	});

	it('honours a usable in-process secret and never touches storage', async () => {
		const supplied = generateNonceSecret();
		const store = new StubStore(null);

		const secret = await resolveNonceSecret(store, supplied);

		// The path the whole test suite depends on: a bootstrap-supplied secret stays exactly what was
		// supplied, so a fixed value in a spec config remains meaningful.
		expect(secret).toBe(supplied);
		expect(store.created).toBe(0);
	});

	it('ignores an unusable in-process secret rather than refusing to start', async () => {
		const store = new StubStore(null);
		const warn = quiet();

		const secret = await resolveNonceSecret(store, Buffer.alloc(8, 0));

		// Loud, not fatal. Refusing to boot would be a dead end: the admin plane is served by this same
		// process, so a server that will not start cannot be repaired through any supported surface.
		expect(isUsableNonceSecret(secret)).toBe(true);
		expect(store.created).toBe(1);
		expect(warn.mock.calls.flat().join(' ')).toMatch(/ignoring the configured/);
		warn.mockRestore();
	});
});

/*
 * Persistence and convergence — spec 014, User Story 3.
 *
 * Run against the real in-memory store rather than a stub, because these are claims about the store
 * and the resolver together: that a restart reuses what is there, and that two instances starting at
 * once end up with the same value.
 */
describe('nonce secret: persistence across restarts', () => {
	it('resolves to the same bytes every time, which is what a restart does', async () => {
		const store = new DPoPNonceSecretStore();

		const first = await resolveNonceSecret(store, undefined);
		// A second resolution against the same store is exactly what the next boot performs.
		const second = await resolveNonceSecret(store, undefined);

		expect(Buffer.from(second).equals(Buffer.from(first))).toBe(true);
	});

	it('keeps nonces verifiable across a rebuilt generator', async () => {
		// SC-006 stated in the terms that actually matter to a client: a nonce handed out before a
		// restart still verifies after it. Two generators built from one secret stand in for the two
		// sides of a restart — the generator is process state, the secret is not.
		const store = new DPoPNonceSecretStore();
		const secret = await resolveNonceSecret(store, undefined);

		const before = new DPoPNonces(secret);
		const after = new DPoPNonces(await resolveNonceSecret(store, undefined));

		expect(after.checkNonce(before.nextNonce())).toBe(true);
	});

	it('refuses a nonce from a different secret, so a replacement costs one retry', async () => {
		// The other half of the same guarantee: if the secret really did change, the old nonce must be
		// refused rather than quietly accepted — the client then retries with the fresh one it is handed.
		const issued = new DPoPNonces(generateNonceSecret()).nextNonce();

		expect(new DPoPNonces(generateNonceSecret()).checkNonce(issued)).toBe(
			false
		);
	});
});

describe('nonce secret: concurrent provisioning', () => {
	it('converges on one secret when two instances start against an empty store', async () => {
		const store = new DPoPNonceSecretStore();
		const warn = quiet();

		const [first, second] = await Promise.all([
			resolveNonceSecret(store, undefined),
			resolveNonceSecret(store, undefined)
		]);

		// Divergence here would mean a client load-balanced across the two instances retrying on
		// use_dpop_nonce forever, since neither would ever accept the other's nonce.
		expect(Buffer.from(first).equals(Buffer.from(second))).toBe(true);
		expect(
			Buffer.from((await store.read()) as Uint8Array).equals(Buffer.from(first))
		).toBe(true);
		warn.mockRestore();
	});

	it('converges when two instances both find an unusable stored secret', async () => {
		const store = new DPoPNonceSecretStore();
		await store.create(Buffer.alloc(32, 9));
		// Force the stored value into an unusable shape, the way a storage round trip would.
		await store.replace(await store.read(), mangled() as unknown as Buffer);
		const warn = quiet();

		const [first, second] = await Promise.all([
			resolveNonceSecret(store, undefined),
			resolveNonceSecret(store, undefined)
		]);

		// The loser's conditional write misses, so it adopts the winner's value rather than installing
		// its own replacement over the top.
		expect(Buffer.from(first).equals(Buffer.from(second))).toBe(true);
		expect(isUsableNonceSecret(await store.read())).toBe(true);
		warn.mockRestore();
	});
});
