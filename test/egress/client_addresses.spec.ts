import { describe, it, beforeAll, afterEach, spyOn, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { mock } from '../fetch_mock.js';
import { clientKeys, registerClient } from 'lib/models/client.js';
import { clientNotifications } from 'lib/shared/client_notifications.js';
import { EgressRefused, guardedFetch, resolver } from 'lib/shared/egress.js';

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

	/*
	 * An address can be written many ways, and URL parsing picks one of them for us:
	 * `[::ffff:169.254.169.254]` arrives as `[::ffff:a9fe:a9fe]`. IPv6 also carries IPv4 inside it in
	 * several standard layouts — mapped, compatible, NAT64, 6to4 — each of which reaches the IPv4 host
	 * named inside. The check has to be about the address, not about how it was spelled.
	 */
	it('refuses a reserved address however it is written', async () => {
		for (const address of [
			'::ffff:a9fe:a9fe',
			'::ffff:169.254.169.254',
			'::ffff:7f00:1',
			'::ffff:0:a9fe:a9fe',
			'::a9fe:a9fe',
			'64:ff9b::a9fe:a9fe',
			'64:ff9b::a00:1',
			'2002:a9fe:a9fe::',
			'2001::1',
			'2001:db8::1',
			'100::1',
			'fec0::1',
			'ff02::1',
			'192.0.0.8',
			'192.0.2.1',
			'198.51.100.1',
			'203.0.113.1',
			'192.88.99.1',
			'255.255.255.255'
		]) {
			resolver.lookup = async () => [address];

			const refused = await guardedFetch('https://target.example.com/x', {
				timeoutMs: 1_000
			}).then(
				() => undefined,
				(err: unknown) => err
			);

			expect(refused, address).toBeInstanceOf(EgressRefused);
			// Named, because a fetch the mock refuses for want of an interceptor is an EgressRefused too.
			expect((refused as EgressRefused).reason, address).toBe(
				'blocked_address'
			);
		}
	});

	it('reaches a public address written in an IPv6 form that carries it', async () => {
		for (const address of ['64:ff9b::5db8:d822', '::ffff:5db8:d822']) {
			resolver.lookup = async () => [address];
			mock('https://target.example.com')
				.intercept({ path: '/x' })
				.reply(200, 'ok');

			const response = await guardedFetch('https://target.example.com/x', {
				timeoutMs: 1_000
			});

			expect(response.status, address).toBe(200);
		}
	});

	it('refuses a key set named by an IPv4-mapped literal without requesting it', async () => {
		const client = await registerClient(
			{
				clientId: 'mapped-jwks-client',
				redirectUris: ['https://client.example.com/cb'],
				token_endpoint_auth_method: 'private_key_jwt',
				jwks_uri: 'https://[::ffff:169.254.169.254]/jwks'
			},
			{ store: false }
		);
		const fetchSpy = spyOn(globalThis, 'fetch');

		await expect(clientKeys(client).asymmetric.refresh()).rejects.toThrow();

		expect(requestsTo(fetchSpy.mock.calls, 'https://[')).toHaveLength(0);
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
