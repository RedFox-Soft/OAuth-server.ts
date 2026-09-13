import { generateKeyPair, exportJWK } from 'jose';
import nanoid from './nanoid.ts';
import { verifyJWKs, type JWKS } from 'lib/configs/verifyJWKs.ts';
import { type asymmetricSigningAlgType } from 'lib/configs/jwaConsts.ts';

/**
 * Generates a single-key JWKS for any asymmetric signing algorithm this server knows.
 *
 * The key type is whatever the algorithm implies — RSA for `RS*`/`PS*`, EC for `ES*`, OKP for
 * `EdDSA`/`Ed25519` — and it is taken from the exported key rather than from a table here, because
 * it is a property of the material jose produced and a second derivation of it could disagree with
 * the key itself. The same goes for `crv` on the EC and OKP forms.
 */
export async function generateJWKS(
	alg: asymmetricSigningAlgType = 'RS256'
): Promise<{ keys: JWKS[] }> {
	const { publicKey, privateKey } = await generateKeyPair(alg, {
		extractable: true
	});

	const set = {
		keys: [
			{
				...(await exportJWK(publicKey)),
				...(await exportJWK(privateKey)),
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
