import { algorithmOf } from '../assertions/id_jag.js';
import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import * as JWT from '../helpers/jwt.js';
import { keysFor } from '../keys/issuer_keys.js';
import type { Standing } from './session.js';

/*
 * `X-Auth-Assertion` (specs/122 R9): the facts the identity headers carry, signed with the project's own key, so an
 * app that verifies it against the project's published keys no longer depends on being reachable only through the
 * proxy. Its audience is the app's address, so an assertion for one app is not one for another, and it lives a
 * minute, because the proxy asks again for every request.
 */

export const ASSERTION_JWT_TYPE = 'foxauth-proxy+jwt';
const ASSERTION_SECONDS = 60;

export async function signAssertion(
	bucket: RequestBucket,
	appAddress: string,
	person: Standing
): Promise<string> {
	const keys = await keysFor(bucket);
	const alg = algorithmOf(keys.signingAlgorithms);
	const jwk = keys.signing.selectForSign({ alg, use: 'sig' }).at(0);
	if (!jwk) {
		throw new Error(`the project holds no ${alg} signing key`);
	}
	return JWT.sign(
		{
			sub: person.accountId,
			email: person.email,
			groups: person.groupIds,
			group_names: person.groupNames
		},
		keys.signing.getKeyObject(jwk),
		alg,
		{
			typ: ASSERTION_JWT_TYPE,
			fields: { kid: jwk.kid },
			audience: appAddress,
			issuer: issuerFor(bucket),
			expiresIn: ASSERTION_SECONDS
		}
	);
}
