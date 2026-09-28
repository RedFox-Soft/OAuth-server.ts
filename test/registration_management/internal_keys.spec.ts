import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { Client } from 'lib/models/client.js';
import { present } from 'test/shape.js';

/*
 * A registration body is wire metadata, and only wire metadata. The client model keeps its base
 * attributes under canonical names (`clientId`, `clientSecret`, `consent.require`, …), and a body that
 * spelled one of those names used to be copied into the record verbatim — after the server's own
 * `client_id`, so it won. That let an unauthenticated registrant overwrite any stored client, the
 * console's own included, or switch off the consent screen for a client of its own.
 */

const json = { 'content-type': 'application/json' };
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const ATTACKER_CALLBACK = 'https://attacker.example/cb';

async function register(metadata: Record<string, unknown> = {}) {
	const res = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'], ...metadata },
		{ headers: json }
	);
	expect(res.status).toBe(201);
	return {
		clientId: present(res.data?.client_id, 'a client_id'),
		token: present(
			res.data?.registration_access_token,
			'a registration access token'
		)
	};
}

/**
 * @proves A client registering or updating itself cannot reach another client's record or switch
 * off its own consent screen by naming the model's internal attributes in its metadata.
 */
describe('a registration body naming internal client attributes', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'registration_management' });
	});

	it('leaves an existing client untouched when a registration names its id under the internal key', async () => {
		const res = await agent.reg.post(
			{
				client_id: 'ignored',
				clientId: 'client',
				redirect_uris: [ATTACKER_CALLBACK],
				token_endpoint_auth_method: 'none'
			},
			{ headers: json }
		);

		expect(res.data?.client_id).not.toBe('client');
		const stored = await adapter('Client').find('client');
		expect(stored?.redirectUris).toEqual(['https://client.example.com/cb']);
		expect(stored?.clientSecret).toBe('secret');
	});

	it('leaves an existing client untouched when an update names its id under the internal key', async () => {
		const own = await register();

		await agent.reg({ clientId: own.clientId }).put(
			{
				client_id: own.clientId,
				clientId: 'client',
				redirect_uris: [ATTACKER_CALLBACK]
			},
			{ headers: { ...json, ...bearer(own.token) } }
		);

		const stored = await adapter('Client').find('client');
		expect(stored?.redirectUris).toEqual(['https://client.example.com/cb']);
	});

	it('keeps the consent screen for a registration that asks to skip it', async () => {
		const { clientId } = await register({ 'consent.require': false });

		const client = await Client.find(clientId);
		expect(client['consent.require']).not.toBe(false);
	});

	it('keeps the consent screen for an update that asks to skip it', async () => {
		const own = await register();

		await agent.reg({ clientId: own.clientId }).put(
			{
				client_id: own.clientId,
				redirect_uris: ['https://client.example.com/cb'],
				'consent.require': false
			},
			{ headers: { ...json, ...bearer(own.token) } }
		);

		const client = await Client.find(own.clientId);
		expect(client['consent.require']).not.toBe(false);
	});
});
