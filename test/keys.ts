import { generateKeyPair, exportJWK } from 'jose';

/*
 * Returned as a spread object rather than jose's own `JWK`: that is an interface, and TypeScript grants
 * an implicit index signature only to anonymous object types — so a `JWK` is not assignable to the
 * `Record<string, …>` shape the key plumbing here speaks (KeyStore's members, seedJwks' parameter).
 * Converting once at this boundary is what keeps every consumer cast-free.
 */
async function generateJWK(alg: string): Promise<Record<string, unknown>> {
	const pair = await generateKeyPair(alg, { extractable: true });
	const jwk = await exportJWK(pair.privateKey);
	return { ...jwk, alg };
}

export default await Promise.all(['RS256', 'ES256', 'EdDSA'].map(generateJWK));

export function stripPrivateJWKFields(key: Record<string, unknown>) {
	const publicKey = structuredClone(key);
	for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
		delete publicKey[k];
	}
	return publicKey;
}
