import { describe, it, expect, beforeAll } from 'bun:test';
import { generateKeyPair, SignJWT } from 'jose';

import bootstrap from '../test_helper.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { assertionKey } from './profile.config.ts';
import { answer, proof, tokenRequest, type KeyPair } from './profile_flow.ts';

function assertion(audience: string | string[]) {
	return new SignJWT({})
		.setProtectedHeader({ alg: 'PS256' })
		.setIssuer('sl1-pkjwt')
		.setSubject('sl1-pkjwt')
		.setAudience(audience)
		.setJti(crypto.randomUUID())
		.setIssuedAt()
		.setExpirationTime('1m')
		.sign(assertionKey.privateKey);
}

/**
 * @proves Under the IPSIE SL1 profile a client assertion is accepted only when its audience is this server's issuer
 * identifier, sent as a string, as SL1 §3.2.1 requires.
 */
describe('the client assertion audience under the IPSIE SL1 profile', () => {
	let keypair: KeyPair;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile' });
		keypair = await generateKeyPair('ES256');
	});

	it('refuses the issuer identifier sent as a one-element list', async () => {
		const res = await tokenRequest(
			{
				grant_type: 'client_credentials',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_assertion: await assertion([ISSUER])
			},
			{ client: 'sl1-pkjwt', dpop: await proof(keypair) }
		);

		expect((await answer(res)).error).toBe('invalid_client');
	});
});
