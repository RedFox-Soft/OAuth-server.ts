import { randomBytes } from 'node:crypto';
import type { SecretStoreInstance } from '../adapters/types.js';

/*
 * The server's pairwise identifier salt, resolved once at startup — the sibling of
 * configs/nonceSecret.ts and configs/keys.ts, which resolve their own material from a store the same
 * way.
 *
 * This module imports nothing but the store's type, and that is load-bearing rather than tidy. Its
 * consumer is addon/tokens.ts, a leaf that half the server imports; if this module reached for
 * adapters/index.ts the way keys.ts does, the resulting cycle would run through the model graph and
 * back into addon/tokens.ts while that module was still evaluating. So the store arrives as a
 * parameter, exactly as the nonce secret's does, and configs/application.ts drives the resolution as
 * a statement — the ordering is then a fact about one file rather than a property of the import graph.
 *
 * What it establishes: by the time the server serves a request, either a usable salt exists or the
 * server knows it has none. There is no third state, and nothing downstream has to guess which.
 */

const SALT_BYTES = 32;

/*
 * The narrowing predicate. A runtime check rather than a type assertion, for the reason task 35 paid
 * for: a buffer written to a document store reads back as the driver's binary wrapper, or as
 * `{ type: 'Buffer', data: [...] }` through a JSON round trip. An assertion would assert exactly the
 * fact that incident disproved.
 *
 * `Uint8Array`, not `Buffer`, and the difference matters in both directions — too strict and a
 * structured clone of a configuration is rejected for no reason (a cloned Buffer downgrades to a
 * plain Uint8Array and hashes identically); too loose and the wrapper shapes above pass. Same
 * reasoning as isUsableNonceSecret, and deliberately not shared with it: one predicate serving two
 * secrets would tie their lengths together, and a future change to either would silently move the
 * other.
 */
export function isUsablePairwiseSalt(value: unknown): value is Uint8Array {
	return value instanceof Uint8Array && value.byteLength === SALT_BYTES;
}

export function generatePairwiseSalt(): Buffer {
	return randomBytes(SALT_BYTES);
}

/*
 * Resolve the salt the server will use, provisioning if there is none — and refusing, rather than
 * repairing, if what is stored cannot be used.
 *
 * That asymmetry with the nonce secret is the whole decision of this feature, so it is worth stating
 * where it lives. The nonce secret replaces an unusable stored value and keeps serving, because the
 * cost is one retry per client. Replacing a salt permanently breaks every relying party's account
 * linkage, and the realistic cause of an unusable value is a storage-layer defect that recurs on
 * every read — so a replacing resolver would reassign every pairwise identifier on every restart
 * while reporting a healthy boot. Returning nothing is how the server declines to invent an identity
 * it cannot reproduce.
 *
 * `configured` is an in-process bootstrap value — the test suite supplies one, and it is the only way
 * in, since the key is absent from the admin settings catalogue. A usable one is honoured verbatim and
 * storage is never touched, which is what makes a fixed salt in a test meaningful. An unusable one is
 * loud but not fatal, for the same reason the nonce secret's is: the administrative plane is served by
 * this same process, so a server that will not start cannot be repaired through any supported surface.
 */
export async function resolvePairwiseSalt(
	store: SecretStoreInstance,
	configured: unknown
): Promise<Uint8Array | null> {
	if (isUsablePairwiseSalt(configured)) {
		return configured;
	}
	if (configured !== undefined) {
		console.warn(
			'ignoring the configured pairwise salt: it is not 32 bytes of material. Using the ' +
				"server's own stored salt instead."
		);
	}

	const stored = await store.read();
	if (isUsablePairwiseSalt(stored)) {
		return stored;
	}

	/*
	 * Absent and unusable are different situations and only one of them is repairable. Nothing stored
	 * is the ordinary first boot of a fresh deployment. Something stored that cannot be used is either
	 * a storage layer that mangles the value or a value someone else wrote, and in both cases the
	 * server's own candidate is the wrong answer: it would be durable nowhere, so every instance and
	 * every restart would disagree.
	 */
	if (stored !== null) {
		console.warn(
			'the stored pairwise salt is not usable 32-byte material, and the server will NOT replace ' +
				'it: a new salt would permanently change every pairwise sub, breaking account linkage at ' +
				'every relying party that uses one. Requests from pairwise clients will be refused until ' +
				'the stored value is repaired. Every other client is served normally.'
		);
		return null;
	}

	/*
	 * `create` hands back what storage actually holds, so one call covers two things: the round-trip
	 * verification (the value came from the datastore, not from this instance's hand), and adoption of
	 * another instance's salt when this one's write did not take effect — which is how simultaneously
	 * starting instances converge instead of each deriving identifiers the others cannot reproduce.
	 *
	 * `replace` is never called, on any path. The salt has no repair path by design.
	 */
	const effective = await store.create(generatePairwiseSalt());

	if (!isUsablePairwiseSalt(effective)) {
		console.warn(
			'the pairwise salt does not survive a storage round trip: a freshly written 32-byte salt ' +
				'read back in an unusable shape. The storage layer cannot carry binary values intact, so ' +
				'the server has no salt it could reproduce after a restart, and will refuse requests from ' +
				'pairwise clients rather than issue identifiers that change on every boot.'
		);
		return null;
	}

	/* Deliberately silent. Provisioning on an empty store is the ordinary path for every fresh
	 * deployment; announcing it would train an operator to ignore this channel, which is where the two
	 * messages above go. */
	return effective;
}

/*
 * The resolved salt, as module state — the same arrangement as JWKS_KEYS in configs/keys.ts, and for
 * the same reason: this is key material single-sourced from a store, not an input to the provider.
 *
 * Held behind an accessor rather than exported directly so that a caller cannot capture a stale
 * binding, and so a test can re-resolve against a store it controls (which is what stands in for a
 * restart) without reloading the module graph.
 */
let resolved: Uint8Array | null = null;

export function pairwiseSalt(): Uint8Array | null {
	return resolved;
}

export async function initPairwiseSalt(
	store: SecretStoreInstance,
	configured?: unknown
): Promise<Uint8Array | null> {
	resolved = await resolvePairwiseSalt(store, configured);
	return resolved;
}
