import { describe, it, expect, beforeAll, afterEach, spyOn } from 'bun:test';
import { jwtVerify } from 'jose';

import bootstrap from '../test_helper.ts';
import { mock } from '../fetch_mock.ts';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { discover, forgetDiscovery } from 'lib/federation/discovery.ts';
import { exchangeCode } from 'lib/federation/flow.ts';
import { keySetFor } from 'lib/federation/jwks.ts';
import { resolver } from 'lib/shared/egress.ts';
import { provider } from './harness.ts';

/*
 * An upstream provider's addresses are an administrator's choice, but not only a super administrator's:
 * any member of a group can add a bucket and configure a provider on it, and the discovery document the
 * issuer serves then names the token endpoint and key set too. Those requests went through plain fetch —
 * redirects followed anywhere, private and link-local addresses reachable, no bound on time or size — and
 * once a provider existed an unauthenticated visitor could set them off again by starting a sign-in.
 */

const PRIVATE = '10.0.0.5';

/* Every name resolves to a public address except the ones named here. */
function resolving(privateHosts: string[]) {
	resolver.lookup = async (host: string) =>
		privateHosts.includes(host) ? [PRIVATE] : ['93.184.216.34'];
}

function requestsTo(calls: readonly (readonly unknown[])[], host: string) {
	return calls.filter(([input]) =>
		String(input instanceof Request ? input.url : input).includes(host)
	);
}

const metadataFor = (origin: string, tokenEndpoint: string) => ({
	issuer: origin,
	authorizationEndpoint: `${origin}/authorize`,
	tokenEndpoint,
	jwksUri: `${origin}/jwks`,
	signingAlgValues: ['RS256'],
	codeChallengeMethods: ['S256'],
	tokenAuthMethods: ['client_secret_post']
});

/**
 * @proves The requests a sign-in through an upstream provider makes never reach a private address,
 * and a discovery document may not point any of them at plain http.
 */
describe('outbound requests to an upstream identity provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	afterEach(() => {
		mock.restore();
	});

	it('does not request a discovery document from a private address', async () => {
		resolving(['idp-private.test']);
		forgetDiscovery('https://idp-private.test');
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(discover('https://idp-private.test')).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, 'idp-private.test')).toHaveLength(0);
	});

	it('refuses a discovery document that sends the code exchange over plain http', async () => {
		resolving([]);
		const origin = 'https://idp-plain.test';
		forgetDiscovery(origin);
		mock(origin)
			.intercept({ path: '/.well-known/openid-configuration' })
			.reply(
				200,
				JSON.stringify({
					issuer: origin,
					authorization_endpoint: `${origin}/authorize`,
					token_endpoint: 'http://idp-plain.test/token',
					jwks_uri: `${origin}/jwks`
				})
			);

		await expect(discover(origin)).rejects.toThrow();
	});

	it('sends no code to a token endpoint at a private address', async () => {
		resolving(['token-private.test']);
		const origin = 'https://idp-token.test';
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(
			exchangeCode(
				provider(origin),
				metadataFor(origin, 'https://token-private.test/token'),
				'upstream-code',
				await issuingBucket(DEFAULT_BUCKET_ID)
			)
		).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, 'token-private.test')).toHaveLength(
			0
		);
	});

	it('does not fetch a key set from a private address', async () => {
		resolving(['jwks-private.test']);
		const fetchSpy = spyOn(globalThis, 'fetch');
		const header = Buffer.from(
			JSON.stringify({ alg: 'RS256', kid: 'k' })
		).toString('base64url');
		const token = `${header}.${Buffer.from('{}').toString('base64url')}.AA`;

		await expect(
			jwtVerify(token, keySetFor('https://jwks-private.test/keys'))
		).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, 'jwks-private.test')).toHaveLength(
			0
		);
	});
});
