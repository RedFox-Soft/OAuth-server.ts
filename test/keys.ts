import { generateKeyPair, exportJWK } from 'jose';

async function generateJWK(alg: string) {
	const pair = await generateKeyPair(alg, { extractable: true });
	const jwk = await exportJWK(pair.privateKey);
	jwk.alg = alg;
	return jwk;
}

export default await Promise.all(['RS256', 'ES256', 'EdDSA'].map(generateJWK));

export function stripPrivateJWKFields(key) {
	const publicKey = structuredClone(key);
	for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
		delete publicKey[k];
	}
	return publicKey;
}
