import { describe, it, afterAll, expect } from 'bun:test';
import { importJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';

import { provider } from 'lib/index.ts';
import instance from 'lib/helpers/weak_cache.ts';
import { seedJwks } from '../test_helper.js';
import { generateJWKS } from 'lib/helpers/jwks.ts';
import { testSigningKeys } from './fixtures.js';

const [rsaA, ecB] = testSigningKeys;

// Relying-party view of the server's public keys: verify tokens against the published JWKS.
function publishedKeySet() {
	const keys = instance(provider).jwks.keys.map((k) => ({ ...k }));
	return createLocalJWKSet({ keys });
}

// Rotation is performed the way a deployment performs it: write the jwksStore and reload, since
// the store is the single source for the server's keys.
describe('key rotation does not invalidate tokens signed by a remaining key (SC-005)', () => {
	afterAll(async () => {
		await seedJwks(testSigningKeys);
	});

	it('a token signed by a key that survives rotation still verifies', async () => {
		// Start with keys [A (RSA), B (EC)].
		await seedJwks([rsaA, ecB]);
		provider.init();

		// Sign a token with B.
		const bPrivate = await importJWK(ecB, 'ES256');
		const token = await new SignJWT({ sub: 'user-1' })
			.setProtectedHeader({ alg: 'ES256', kid: ecB.kid })
			.setIssuedAt()
			.setExpirationTime('5m')
			.sign(bPrivate);

		// It verifies against the current published set.
		await jwtVerify(token, publishedKeySet());

		// Rotate: add a new key C, remove the superseded A, keep B.
		const {
			keys: [cKey]
		} = await generateJWKS('RS256');
		await seedJwks([ecB, cKey]);
		provider.init();

		// The B-signed token STILL verifies because B remains published.
		const { payload } = await jwtVerify(token, publishedKeySet());
		expect(payload.sub).toBe('user-1');

		// Published set reflects the rotation: B and C present, A gone.
		const publishedKids = instance(provider).jwks.keys.map((k) => k.kid);
		expect(publishedKids).toContain(ecB.kid);
		expect(publishedKids).toContain(cKey.kid);
		expect(publishedKids).not.toContain(rsaA.kid);
	});
});
