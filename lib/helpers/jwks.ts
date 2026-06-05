import { generateKeyPair, exportJWK } from 'jose';
import nanoid from './nanoid.ts';
import { type StaticRSAKey } from 'lib/configs/verifyJWKs.ts';

/**
 * Generates a JWKS (JSON Web Key Set) for RSA256
 * @returns {object} The JWKS object
 */
export async function generateJWKS(
	alg: 'RS256' | 'RS384' | 'RS512' = 'RS256'
): Promise<{ keys: [StaticRSAKey] }> {
	const { publicKey, privateKey } = await generateKeyPair(alg, {
		extractable: true
	});

	const jwk = {
		...(await exportJWK(publicKey)),
		...(await exportJWK(privateKey)),
		kty: 'RSA',
		use: 'sig',
		alg,
		kid: nanoid()
	} as StaticRSAKey;

	return { keys: [jwk] };
}
