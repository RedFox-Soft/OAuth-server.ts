import { describe, it, expect, beforeEach } from 'bun:test';

import { SingletonSecretStore } from 'lib/adapters/memory/singletonSecretStore.ts';

// The singleton-secret store contract, salt instance —
// specs/023-pairwise-identifier-salt/contracts/pairwise-salt-store.md.
//
// Semantics 1-6 are the same three operations the DPoP nonce secret already relies on, and since
// spec 023 both documents are served by ONE class per adapter rather than two copied ones. They are
// pinned against that class by test/storage_contract/dpop_nonce_secret.spec.ts and are deliberately
// not restated here: re-asserting seven identical cases against the same code would grow the suite
// without growing its coverage.
//
// What is new with a second document, and therefore what this file is for, is semantic 7 — two
// instances over one storage area never observe or overwrite each other's record. That is the one
// property a copied class could not get wrong and a parameterized one can.
//
// Memory implementation only, for the reason given in the sibling spec: lib/adapters/mongodb/db.ts
// opens its connection at module scope and throws without MONGODB_URI, which this suite deliberately
// lacks. In the memory adapter an instance *is* the document, so isolation holds by construction —
// which is exactly why it is worth pinning. A future refactor to a module-level map keyed by name
// would still satisfy every other case in this directory and would break only this one.

const bytes = (fill: number): Buffer => Buffer.alloc(32, fill);

describe('SingletonSecretStore (memory): pairwise salt instance', () => {
	let salt: SingletonSecretStore;

	beforeEach(() => {
		salt = new SingletonSecretStore('pairwiseSalt');
	});

	it('reads nothing before the salt has been provisioned', async () => {
		expect(await salt.read()).toBeNull();
	});

	it('provisions once and reads back what it wrote', async () => {
		expect(await salt.create(bytes(7))).toEqual(bytes(7));
		expect(await salt.read()).toEqual(bytes(7));
	});

	it('never overwrites an existing salt on create', async () => {
		// The salt resolver's whole safety property rests on this: a second instance that finds a salt
		// already there must adopt it rather than install its own, or two instances issue mutually
		// unrecognisable identifiers.
		await salt.create(bytes(7));

		expect(await salt.create(bytes(8))).toEqual(bytes(7));
		expect(await salt.read()).toEqual(bytes(7));
	});
});

describe('SingletonSecretStore (memory): instance isolation', () => {
	it('keeps two documents in one area apart', async () => {
		const salt = new SingletonSecretStore('pairwiseSalt');
		const nonce = new SingletonSecretStore('dpopNonceSecret');

		await salt.create(bytes(7));

		// Provisioning the salt must leave the nonce secret absent. Getting this wrong in the MongoDB
		// adapter — a shared _id rather than one derived per document name — would mean the two
		// singletons silently overwrote each other, and the symptom would be pairwise identifiers and
		// DPoP nonces breaking together for no visible common reason.
		expect(await nonce.read()).toBeNull();

		await nonce.create(bytes(8));

		expect(await salt.read()).toEqual(bytes(7));
		expect(await nonce.read()).toEqual(bytes(8));
	});

	it('does not let one document replace the other', async () => {
		const salt = new SingletonSecretStore('pairwiseSalt');
		const nonce = new SingletonSecretStore('dpopNonceSecret');

		const observed = await salt.create(bytes(7));
		await nonce.create(bytes(8));

		// The salt's own value, offered as the observed value to the other document's conditional
		// write. It must not match.
		expect(await nonce.replace(observed, bytes(9))).toEqual(bytes(8));
		expect(await salt.read()).toEqual(bytes(7));
	});
});
