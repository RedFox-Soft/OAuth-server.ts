import {
	describe,
	it,
	beforeAll,
	afterEach,
	spyOn,
	mock,
	expect
} from 'bun:test';
import { strict as assert } from 'node:assert';

import moment from 'moment';

import * as JWT from '../../lib/helpers/jwt.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap from '../test_helper.js';
import initializeClients from '../../lib/helpers/initialize_clients.ts';
import { IdToken } from 'lib/models/id_token.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';

const keys = [
	{
		kty: 'EC',
		x: 'kD4NZtqcBOZIxftx1mj2YivhZAIHthDu3NI2QvC0QDY',
		y: 'pwAHxPuyDIQJJeoMvQ7uI7LjOfx8cw8fy37YwzGnxcA',
		crv: 'P-256'
	}
];

function setResponse(
	body = {
		keys
	},
	status = 200,
	headers = {}
) {
	spyOn(globalThis, 'fetch').mockResolvedValue(
		new Response(typeof body === 'string' ? body : JSON.stringify(body), {
			status,
			headers
		})
	);
}

// NOTE: these tests are to be run sequentially, picking one random won't pass
describe('client keystore refresh', () => {
	beforeAll(async function () {
		await bootstrap(import.meta.url, { config: 'client_keystore' })();

		initializeClients.call(provider, [
			{
				clientId: 'client',
				clientSecret: 'secret',
				redirectUris: ['https://client.example.com/cb'],
				jwks_uri: 'https://client.example.com/jwks',
				id_token_signed_response_alg: 'HS256',
				id_token_encrypted_response_alg: 'ECDH-ES',
				id_token_encrypted_response_enc: 'A128CBC-HS256'
			}
		]);
	});

	afterEach(() => {
		mock.restore();
	});

	it('gets the jwks from the uri (and does only one request concurrently)', async function () {
		setResponse();

		const client = await Client.find('client');
		await Promise.all([
			client.asymmetricKeyStore.refresh(),
			client.asymmetricKeyStore.refresh()
		]);

		expect(globalThis.fetch.mock.calls).toHaveLength(1);
		expect(
			client.asymmetricKeyStore.selectForSign({ kty: 'EC' })
		).not.toHaveLength(0);
	});

	it('fails when private keys are encountered (and does only one request concurrently)', async function () {
		setResponse({
			keys: [
				{
					kty: 'EC',
					x: 'vu2xH_Rzev40voYeW5clt1BVjyV1sFld60ZfecW5RbM',
					y: 'bPvB8qkseGy38m8HUQKbsmvtBE_9OEBuUmpJgTRIg28',
					crv: 'P-256',
					d: '9YzpRwRvpKsStP7uPqs0yRvbregkHMYIFy-cG_KJCsY'
				}
			]
		});

		const client = await Client.find('client');
		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		return Promise.all([
			assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
				expect(err).toBeInstanceOf(Error);
				expect(err.message).toBe('invalid_client_metadata');
				expect(err.error_description).toEqual(
					'client JSON Web Key Set failed to be refreshed'
				);
				return true;
			}),
			assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
				expect(err).toBeInstanceOf(Error);
				expect(err.message).toBe('invalid_client_metadata');
				expect(err.error_description).toEqual(
					'client JSON Web Key Set failed to be refreshed'
				);
				return true;
			})
		]);
	});

	it('adds new keys', async function () {
		const client = await Client.find('client');
		keys.push({
			kty: 'EC',
			x: 'pPrd-y2inidf7iiYmB_ymaTWZrBresjbgmnjLzIOiBY',
			y: 'Wkxz6RSvg9xEvDLppPJ0Bi7psTF974mXSlpuf_x120c',
			crv: 'P-256'
		});
		setResponse();

		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		await client.asymmetricKeyStore.refresh();
		expect(client.asymmetricKeyStore.selectForSign({ kty: 'EC' })).toHaveLength(
			2
		);
	});

	it('removes not found keys', async function () {
		setResponse({ keys: [] });

		const client = await Client.find('client');
		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		await client.asymmetricKeyStore.refresh();

		expect(client.asymmetricKeyStore.selectForSign({ kty: 'EC' })).toHaveLength(
			0
		);
	});

	it('only accepts 200s', async function () {
		setResponse({ keys: [] }, 201);

		const client = await Client.find('client');
		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
			expect(err).toBeInstanceOf(Error);
			expect(err.message).toBe('invalid_client_metadata');
			expect(err.error_description).toEqual(
				'client JSON Web Key Set failed to be refreshed'
			);
			return true;
		});
	});

	it('only accepts parseable json', async function () {
		setResponse('not json');

		const client = await Client.find('client');
		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
			expect(err).toBeInstanceOf(Error);
			expect(err.message).toBe('invalid_client_metadata');
			expect(err.error_description).toEqual(
				'client JSON Web Key Set failed to be refreshed'
			);
			return true;
		});
	});

	it('only accepts keys as array', async function () {
		setResponse({ keys: {} });

		const client = await Client.find('client');
		spyOn(client.asymmetricKeyStore, 'fresh').mockReturnValue(false);
		return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
			expect(err).toBeInstanceOf(Error);
			expect(err.message).toBe('invalid_client_metadata');
			expect(err.error_description).toEqual(
				'client JSON Web Key Set failed to be refreshed'
			);
			return true;
		});
	});

	describe('caching', () => {
		it('uses expires caching header to determine stale states', async function () {
			const client = await Client.find('client');
			const until = moment().add(2, 'hours').toDate();

			setResponse(undefined, undefined, {
				Expires: until.toUTCString()
			});

			const freshUntil = epochTime(until);

			const spy = spyOn(client.asymmetricKeyStore, 'fresh');
			spy.mockImplementation(function () {
				spy.mockRestore();
				return false;
			});
			await client.asymmetricKeyStore.refresh();
			expect(client.asymmetricKeyStore.fresh()).toBe(true);
			expect(client.asymmetricKeyStore.stale()).toBe(false);
			expect(client.asymmetricKeyStore.freshUntil).toBe(freshUntil);
		});

		it('ignores the cache-control one when expires is provided', async function () {
			const client = await Client.find('client');
			const until = moment().add(2, 'hours').toDate();

			setResponse(undefined, undefined, {
				Expires: until.toUTCString(),
				'Cache-Control': 'private, max-age: 3600'
			});

			const freshUntil = epochTime(until);

			const spy = spyOn(client.asymmetricKeyStore, 'fresh');
			spy.mockImplementation(function () {
				spy.mockRestore();
				return false;
			});
			await client.asymmetricKeyStore.refresh();
			expect(client.asymmetricKeyStore.fresh()).toBe(true);
			expect(client.asymmetricKeyStore.stale()).toBe(false);
			expect(client.asymmetricKeyStore.freshUntil).toBe(freshUntil);
		});

		it('uses the max-age if Cache-Control is missing', async function () {
			const client = await Client.find('client');

			setResponse(undefined, undefined, {
				'Cache-Control': 'private, max-age=3600'
			});

			const freshUntil = epochTime() + 3600;

			const spy = spyOn(client.asymmetricKeyStore, 'fresh');
			spy.mockImplementation(function () {
				spy.mockRestore();
				return false;
			});
			await client.asymmetricKeyStore.refresh();
			expect(client.asymmetricKeyStore.fresh()).toBe(true);
			expect(client.asymmetricKeyStore.stale()).toBe(false);
			expect(
				Math.abs(client.asymmetricKeyStore.freshUntil - freshUntil)
			).toBeLessThanOrEqual(1);
		});

		it('falls back to 1 minute throttle if no caching header is found', async function () {
			const client = await Client.find('client');

			setResponse();

			const freshUntil = epochTime() + 60;

			const spy = spyOn(client.asymmetricKeyStore, 'fresh');
			spy.mockImplementation(function () {
				spy.mockRestore();
				return false;
			});
			await client.asymmetricKeyStore.refresh();
			expect(client.asymmetricKeyStore.fresh()).toBe(true);
			expect(client.asymmetricKeyStore.stale()).toBe(false);
			expect(
				Math.abs(client.asymmetricKeyStore.freshUntil - freshUntil)
			).toBeLessThanOrEqual(1);
		});
	});

	describe('refreshing', () => {
		it('when a stale keystore is passed to JWT verification it gets refreshed when verification fails', async function () {
			setResponse();

			const client = await Client.find('client');
			client.asymmetricKeyStore.freshUntil = epochTime() - 1;
			return assert.rejects(
				JWT.verify(
					'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgA',
					client.asymmetricKeyStore
				)
			);
		});

		it('refreshes stale keystores before id_token encryption', async function () {
			setResponse();

			const client = await Client.find('client');
			client.asymmetricKeyStore.freshUntil = epochTime() - 1;
			expect(client.asymmetricKeyStore.stale()).toBe(true);

			const token = new IdToken(client, { foo: 'bar' });

			await token.issue('idtoken');
		});
	});
});
