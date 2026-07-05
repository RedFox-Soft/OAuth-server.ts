import { jwksStore } from '../adapters/index.js';
import { generateJWKS } from '../helpers/jwks.js';
import { verifyJWKs, type JWKS } from './verifyJWKs.js';
import type { JWKSStoreInstance } from '../adapters/types.js';

/*
 * keys
 *
 * The authorization server's signing/decryption keys live in the persistent key store (the
 * `jwksStore` adapter), not in an environment variable. Keys are read once at initialization.
 *
 * For a MongoDB deployment the initial signing key is provisioned when the database schema is
 * created (see database/mongodb.ts). This loader keeps an equivalent fallback: on an empty store it
 * generates and persists a single RS256 signing keypair, so the in-memory adapter and any
 * un-provisioned store still reach a working, token-signing state with no manual configuration. A
 * non-empty store is reused verbatim and never has a key generated for it.
 *
 * Rotation is applied by mutating the store out of band and reloading the server.
 */
export async function resolveKeys(store: JWKSStoreInstance): Promise<JWKS[]> {
	let keys = await store.getAll();

	if (keys.length === 0) {
		const {
			keys: [generated]
		} = await generateJWKS('RS256');
		// generateJWKS always assigns a kid; it is present at runtime.
		await store.set(generated.kid as string, generated as JWKS);
		keys = await store.getAll();
	}

	const jwks = { keys };
	// Throws with a clear message on an invalid key set (unsupported type, missing field, dup kid).
	verifyJWKs(jwks);

	return jwks.keys;
}

export const JWKS_KEYS: JWKS[] = await resolveKeys(jwksStore);
