import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { forgetDiscovery } from 'lib/federation/discovery.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { mock } from '../fetch_mock.ts';
import { CLIENT, get, provider, seedBucket } from './harness.ts';

const ISSUER = 'https://sso.example.org';

function stubDiscovery(): void {
	forgetDiscovery(ISSUER);
	mock(ISSUER)
		.intercept({ path: '/.well-known/openid-configuration' })
		.reply(
			200,
			JSON.stringify({
				issuer: ISSUER,
				authorization_endpoint: `${ISSUER}/authorize`,
				token_endpoint: `${ISSUER}/token`,
				jwks_uri: `${ISSUER}/keys`,
				response_types_supported: ['code'],
				id_token_signing_alg_values_supported: ['RS256'],
				code_challenge_methods_supported: ['S256']
			}),
			{ headers: { 'content-type': 'application/json' } }
		);
}

/* The provider's authorize address FoxAuth sends the browser to, for an authorization request with `extra`. */
async function upstreamFor(extra: Record<string, string>): Promise<URL> {
	const auth = new AuthorizationRequest({
		client_id: CLIENT,
		scope: 'openid',
		...extra
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie') ?? '';
	const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);
	return new URL(start.location);
}

/**
 * @proves A sign-in demanded fresh is asked of the person's outside provider fresh too, so a person who signed in to
 * their provider hours ago does not count as having just signed in (specs/124 FR-021).
 */
describe('a fresh sign-in through an outside provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(async () => {
		resetAdminMemoryStores();
		mock.restore();
		stubDiscovery();
		await seedBucket(CLIENT, { federation: [provider(ISSUER)] });
	});

	it('asks the provider for a fresh sign-in, with the same maximum age, when the request carries one', async () => {
		const authorize = await upstreamFor({ max_age: '300' });

		expect(authorize.origin).toBe(ISSUER);
		expect(authorize.searchParams.get('prompt')).toBe('login');
		expect(authorize.searchParams.get('max_age')).toBe('300');
	});

	it('asks the provider for nothing more when the request did not ask for a fresh sign-in', async () => {
		const authorize = await upstreamFor({});

		expect(authorize.origin).toBe(ISSUER);
		expect(authorize.searchParams.get('prompt')).toBeNull();
		expect(authorize.searchParams.get('max_age')).toBeNull();
	});
});
