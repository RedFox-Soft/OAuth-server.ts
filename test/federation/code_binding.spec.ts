import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { mock } from '../fetch_mock.ts';
import { forgetDiscovery } from 'lib/federation/discovery.ts';
import {
	KNOWN_PROVIDERS,
	issuerForKnownProvider,
	type KnownProvider
} from 'lib/consts/known_providers.ts';
import {
	CLIENT,
	get,
	provider,
	seedBucket,
	startInteraction
} from './harness.ts';

/*
 * The authorization code is bound to the request that asked for it, for every recognised provider that
 * supports the binding — **including the ones that support it without saying so**.
 *
 * This is the guard for a real, previously shipped weakness rather than a hypothetical one. Support was
 * inferred purely from what a provider advertised, and of the four recognised providers three support the
 * binding while only one publishes a challenge method: one recommends it in its own documentation and
 * advertises nothing, one has supported it since July 2025 and publishes no metadata document at all, and
 * one is unresolved. So the old rule silently dropped the binding from three of four legs.
 *
 * Every upstream here therefore advertises **no** challenge method. If a stub advertised one, this would
 * pass for the wrong reason: the old inference would satisfy it.
 */

const json = { headers: { 'content-type': 'application/json' } };

/*
 * Stubs discovery for an entry, advertising no challenge method. Built from the entry itself rather than
 * from a per-provider fixture, so an entry added later is covered with no new scaffolding — and a
 * provider that publishes nothing needs none.
 */
function stubDiscovery(entry: KnownProvider, issuer: string): void {
	if (entry.protocol.kind === 'profile_api') return;

	forgetDiscovery(issuer);
	const url = new URL(issuer);
	/*
	 * Built the way `discover` builds it — trailing slash stripped first — so a root-path issuer does not
	 * end up intercepted at a doubled slash it will never request.
	 */
	const discoveryUrl = new URL(
		`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
	);
	mock(url.origin)
		.intercept({ path: discoveryUrl.pathname })
		.reply(
			200,
			JSON.stringify({
				issuer,
				authorization_endpoint: `${url.origin}/authorize`,
				token_endpoint: `${url.origin}/token`,
				jwks_uri: `${url.origin}/keys`,
				response_types_supported: ['code'],
				id_token_signing_alg_values_supported: ['RS256'],
				token_endpoint_auth_methods_supported: ['client_secret_post']
			}),
			json
		);
}

/**
 * @proves For every recognised provider whose definition states the authorization code can be bound
 * to the request that asked for it, the outbound authorization request carries that binding — even
 * where the provider's own published metadata advertises no method for it.
 */
describe('binding the authorization code to its request', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
		mock.restore();
	});

	it('carries the binding for every recognised provider that states it is supported, and none for one that does not', async () => {
		/*
		 * Enumerated from the running catalogue, not from a list written here: the defect this closes is the
		 * entry somebody adds later whose binding is inferred from metadata again, and no example naming a
		 * particular provider can close that.
		 */
		expect(KNOWN_PROVIDERS.length).toBeGreaterThan(0);

		for (const entry of KNOWN_PROVIDERS) {
			const issuer = issuerForKnownProvider(entry, { tenant: 'a-tenant-id' });
			expect(issuer).toBeDefined();
			stubDiscovery(entry, issuer as string);

			await seedBucket(CLIENT, {
				federation: [
					provider(issuer as string, {
						id: entry.defaultProviderId,
						clientId: 'stub-client',
						scopes: [...entry.scopes],
						...(entry.credential.kind === 'secret'
							? { clientSecret: 'stub-secret' }
							: {
									clientSecret: undefined,
									teamId: 'ABCDE12345',
									keyId: 'KEY1234567',
									signingKey: 'unused — leg one signs nothing'
								})
					})
				]
			});

			const { uid, cookie } = await startInteraction();
			const start = await get(
				`/ui/${uid}/federation/${entry.defaultProviderId}/start`,
				cookie
			);
			expect(start.location).not.toBe('');
			const authorize = new URL(start.location);

			if (entry.codeBinding === 'S256') {
				expect(
					authorize.searchParams.get('code_challenge'),
					`${entry.catalogueId} states the binding is supported but sent none`
				).toBeTruthy();
				expect(authorize.searchParams.get('code_challenge_method')).toBe(
					'S256'
				);
			} else {
				/*
				 * Nothing is sent where support is unresolved, and that is deliberate rather than an omission:
				 * a provider that rejects a parameter it does not recognise fails sign-in for all of its
				 * users, so a missing binding is a weakness while a rejected request is a total outage.
				 */
				expect(
					authorize.searchParams.get('code_challenge'),
					`${entry.catalogueId} does not state the binding is supported, so none may be sent`
				).toBeNull();
			}

			resetAdminMemoryStores();
			mock.restore();
		}
	});
});
