import { generateKeyPair, exportJWK } from 'jose';
import nanoid from './nanoid.ts';
import { verifyJWKs, type JWKS } from 'lib/configs/verifyJWKs.ts';

/**
 * Generates a JWKS (JSON Web Key Set) for RSA256
 * @returns {object} The JWKS object
 */
export async function generateJWKS(
	alg: 'RS256' | 'RS384' | 'RS512' = 'RS256'
): Promise<{ keys: JWKS[] }> {
	const { publicKey, privateKey } = await generateKeyPair(alg, {
		extractable: true
	});

	const set = {
		keys: [
			{
				...(await exportJWK(publicKey)),
				...(await exportJWK(privateKey)),
				kty: 'RSA',
				use: 'sig',
				alg,
				kid: nanoid()
			}
		]
	};

	// Validated, not asserted: jose types every JWK member as optional, so a cast here would be an
	// unchecked claim that it produced a complete RSA private key. This is the one place a generated
	// key enters the app, and verifyJWKs is the same check the key store's contents go through — so
	// it both proves the key is well-formed and types the result as normalized, sparing every caller
	// the `key.kid as string` / `key as JWKS` this used to force on them.
	verifyJWKs(set);

	return set;
}
