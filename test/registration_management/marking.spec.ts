import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { Client } from 'lib/models/client.js';
import { markRegistrationUsed } from 'lib/models/client/dynamic_registration.ts';
import { present } from 'test/shape.js';

/*
 * The two server-owned facts about a self-registered client — that the server created it on request,
 * and that it has since completed an authorization — are not metadata the client sends, so an update
 * built from the client's own body must carry them over. Losing the first lifts the refusal of
 * self-registered clients on the administrative MCP surface and has the console show the client as
 * an administrator's; losing only the second puts a client in use back within reach of the sweep
 * that deletes unused registrations.
 */

const json = { 'content-type': 'application/json' };
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

async function registerAndUpdate(
	beforeUpdate?: (clientId: string) => Promise<void>
) {
	const res = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'] },
		{ headers: json }
	);
	expect(res.status).toBe(201);
	const clientId = present(res.data?.client_id, 'a client_id');
	const token = present(
		res.data?.registration_access_token,
		'a registration access token'
	);

	await beforeUpdate?.(clientId);

	const update = await agent.reg({ clientId }).put(
		{
			client_id: clientId,
			redirect_uris: ['https://client.example.com/other/cb']
		},
		{ headers: { ...json, ...bearer(token) } }
	);
	expect(update.status).toBe(200);

	return clientId;
}

/**
 * @proves A self-registered client stays marked as self-registered, and as used once it has been,
 * after it updates its own registration.
 */
describe('updating a dynamically created registration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'registration_management' });
	});

	it('stays marked as dynamically registered after an update', async () => {
		const clientId = await registerAndUpdate();

		const stored = await adapter('Client').find(clientId);
		expect(stored?.registeredDynamically).toBe(true);
	});

	it('stays marked as used after an update once it has completed an authorization', async () => {
		const clientId = await registerAndUpdate(async (id) => {
			await markRegistrationUsed(await Client.find(id));
		});

		const stored = await adapter('Client').find(clientId);
		expect(stored?.registrationUsedAt).toBeNumber();
	});
});
