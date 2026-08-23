import { randomBytes } from 'node:crypto';
import type { SecretStoreInstance } from '../adapters/types.js';

/*
 * The server's DPoP nonce secret, resolved once at startup — the sibling of configs/keys.ts, which
 * resolves signing keys from a store the same way.
 *
 * This module imports nothing but the store's type, and takes both the store and any in-process
 * candidate as parameters. That is what lets configs/application.ts drive it as a statement between
 * loading the persisted settings and validating them, with no import cycle: the ordering is then a
 * fact about one file rather than a property of the import graph.
 *
 * The invariant it establishes: by the time the server serves a request, a usable secret exists.
 * Nothing downstream has to ask whether one does.
 */

const SECRET_BYTES = 32;

/*
 * The narrowing predicate, and the whole defence. A runtime check rather than a type assertion,
 * because the defect this feature closes is a value arriving in a shape the declared type calls
 * impossible: a buffer written to a document store reads back as the driver's binary wrapper, or as
 * `{ type: 'Buffer', data: [...] }` through a JSON round trip. An assertion would restore exactly the
 * blindness that produced the bug — every DPoP request throwing a bare TypeError from the nonce
 * generator's constructor.
 *
 * `Uint8Array`, not `Buffer`, and the difference is load-bearing in both directions. Too loose and
 * the wrapper shapes above slip through: neither is a Uint8Array, so both are still caught. Too
 * strict — `Buffer.isBuffer` — and legitimate values are rejected instead, because a structured clone
 * of a configuration downgrades a Buffer to a plain Uint8Array, which derives nonces perfectly well
 * (hkdf accepts any byte array). Rejecting that would fail a valid deployment to guard against
 * nothing, which is the same class of mistake as the bug, pointed the other way.
 */
export function isUsableNonceSecret(value: unknown): value is Uint8Array {
	return value instanceof Uint8Array && value.byteLength === SECRET_BYTES;
}

export function generateNonceSecret(): Buffer {
	return randomBytes(SECRET_BYTES);
}

/*
 * Thrown only when storage cannot carry the value: the server wrote a secret it had just generated,
 * read it back, and got something it cannot use. That is a broken persistence layer rather than
 * anything an operator configured, and it is reported as one — because the alternative is replacing
 * the secret on every single boot while reporting healthy, so nonces silently never survive a restart.
 */
function roundTripFailure(): Error {
	return new Error(
		'the DPoP nonce secret does not survive a storage round trip: a freshly written 32-byte ' +
			'secret read back in an unusable shape. The storage layer cannot carry binary values ' +
			'intact; the server will not serve DPoP requests it cannot answer.'
	);
}

/*
 * Resolve the secret the server will use, provisioning or repairing as needed.
 *
 * `configured` is an in-process bootstrap value (the test suite supplies one, and it is the only way
 * in — the key is absent from the admin settings catalog, so no operator can set it). A usable one is
 * honoured verbatim and storage is never touched, which is what keeps a fixed test secret meaningful.
 *
 * An unusable configured value is ignored rather than fatal. Refusing to boot on it would be a dead
 * end: the administrative plane is served by this same process, so a server that will not start
 * cannot be repaired through any supported surface. It is loud instead of fatal.
 */
export async function resolveNonceSecret(
	store: SecretStoreInstance,
	configured: unknown
): Promise<Uint8Array> {
	if (isUsableNonceSecret(configured)) {
		return configured;
	}
	if (configured !== undefined) {
		console.warn(
			'ignoring the configured dpop.nonceSecret: it is not a 32-byte Buffer. Using the ' +
				"server's own stored secret instead."
		);
	}

	const stored = await store.read();
	if (isUsableNonceSecret(stored)) {
		return stored;
	}

	/*
	 * Both writes hand back what storage actually holds, so one branch covers three things at once:
	 * the round-trip verification (the value came from the datastore, not from this instance's hand),
	 * and adoption of another instance's value when this one's write did not take effect — which is
	 * how simultaneously starting instances converge instead of each serving nonces the others reject.
	 */
	const effective =
		stored === null
			? await store.create(generateNonceSecret())
			: await store.replace(stored, generateNonceSecret());

	if (!isUsableNonceSecret(effective)) {
		throw roundTripFailure();
	}

	/*
	 * Said only when something was silently changed on the operator's behalf, and never with the value
	 * in it. First-boot provisioning is deliberately silent: it is the ordinary path for every fresh
	 * deployment, so announcing it would train an operator to ignore this line — which is the one line
	 * that matters when a stored secret was thrown away.
	 */
	if (stored !== null) {
		console.warn(
			'replaced the stored DPoP nonce secret: the stored value was not usable 32-byte material. ' +
				'Nonces issued under the previous value will be refused once, and clients will retry ' +
				'with a fresh one.'
		);
	}

	return effective;
}
