import { describe, it, beforeAll, afterEach, spyOn, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { mock } from '../fetch_mock.js';
import { clientKeys, registerClient } from 'lib/models/client.js';
import { clientNotifications } from 'lib/shared/client_notifications.js';

/*
 * Addresses a client names in its own metadata, which this server then contacts: the sector document,
 * the published key set and the back-channel logout endpoint. Whoever registers a client — through
 * dynamic registration, or a client ID metadata document with no registration at all — chooses them,
 * so each is an outbound request made on a stranger's behalf. They were plain `fetch` calls: redirects
 * followed wherever they led, no refusal of a private or link-local address, no bound on time or size,
 * and for the sector document the status the target answered repeated back in the refusal — enough to
 * map ports on the network behind this server and to reach the cloud metadata endpoint.
 */

const PRIVATE = 'https://10.0.0.5';

function requestsTo(calls: readonly (readonly unknown[])[], origin: string) {
	return calls.filter(([input]) =>
		String(input instanceof Request ? input.url : input).startsWith(origin)
	);
}

function pairwiseWithSector(sector: string) {
	return registerClient(
		{
			clientId: 'sector-client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			sector_identifier_uri: sector,
			subjectType: 'pairwise'
		},
		{ store: false }
	);
}

/**
 * @proves An address a client names in its metadata is never contacted when it is private, loopback
 * or link-local, directly or through a redirect, and a refusal does not report what the target
 * answered.
 */
describe('outbound requests to an address a client supplied', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
	});

	it('refuses a sector document on a private address without requesting it', async () => {
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(pairwiseWithSector(`${PRIVATE}/sector`)).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, PRIVATE)).toHaveLength(0);
	});

	it('refuses a sector document whose redirect leads to a private address', async () => {
		mock('https://sector.example.com')
			.intercept({ path: '/sector' })
			.reply(302, '', { headers: { location: `${PRIVATE}/sector` } });
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(
			pairwiseWithSector('https://sector.example.com/sector')
		).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, PRIVATE)).toHaveLength(0);
	});

	/*
	 * The other half of the case above, and what makes it mean something: redirects are followed, one
	 * checked hop at a time, rather than refused outright or left to the platform.
	 */
	it('follows a sector redirect to a public address', async () => {
		mock('https://sector.example.com')
			.intercept({ path: '/sector' })
			.reply(302, '', {
				headers: { location: 'https://cdn.example.com/sector.json' }
			});
		mock('https://cdn.example.com')
			.intercept({ path: '/sector.json' })
			.reply(200, JSON.stringify(['https://client.example.com/cb']));

		const client = await pairwiseWithSector(
			'https://sector.example.com/sector'
		);

		expect(client.clientId).toBe('sector-client');
	});

	it('does not repeat the status a sector host answered in its refusal', async () => {
		mock('https://sector.example.com')
			.intercept({ path: '/sector' })
			.reply(403, 'forbidden');

		const refusal = await pairwiseWithSector(
			'https://sector.example.com/sector'
		).catch((err: unknown) => err);

		expect(JSON.stringify(refusal)).not.toContain('403');
		expect(String(refusal)).not.toContain('403');
	});

	it('refuses to retrieve a key set from a private address', async () => {
		const client = await registerClient(
			{
				clientId: 'jwks-client',
				redirectUris: ['https://client.example.com/cb'],
				token_endpoint_auth_method: 'private_key_jwt',
				jwks_uri: `${PRIVATE}/jwks`
			},
			{ store: false }
		);
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(clientKeys(client).asymmetric.refresh()).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, PRIVATE)).toHaveLength(0);
	});

	it('sends no back-channel logout to a private address', async () => {
		const client = await registerClient(
			{
				clientId: 'logout-client',
				clientSecret: 'secret',
				redirectUris: ['https://client.example.com/cb'],
				backchannel_logout_uri: `${PRIVATE}/logout`
			},
			{ store: false }
		);
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(
			clientNotifications.logout(client, 'subject', undefined)
		).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, PRIVATE)).toHaveLength(0);
	});
});
