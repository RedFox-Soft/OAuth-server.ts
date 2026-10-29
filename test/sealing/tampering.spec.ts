import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { agent, seedClient } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { TestAdapter } from '../models.js';
import { isSealed } from 'lib/sealing/seal.ts';
import { client } from './sealing.config.ts';

const OTHER = {
	clientId: 'sealing-other',
	clientSecret: 'other-secret-other-secret-other-secret',
	grantTypes: ['client_credentials'],
	responseTypes: [],
	redirectUris: [],
	scope: 'api:read'
};

function stored(clientId: string): Record<string, unknown> {
	const record = TestAdapter.for('Client').syncFind(clientId);
	if (!record) throw new Error(`no stored client ${clientId}`);
	return record;
}

/* seedClient seals after it returns; the cases below are about the sealed record. */
async function sealedSecretOf(clientId: string): Promise<string> {
	for (let attempt = 0; attempt < 50; attempt += 1) {
		const secret = stored(clientId).clientSecret;
		if (typeof secret === 'string' && isSealed(secret)) return secret;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`the secret of ${clientId} was never sealed`);
}

async function tokenStatus(clientId: string, secret: string): Promise<number> {
	const { status } = await agent.token.post(
		{ grant_type: 'client_credentials', scope: 'api:read' },
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, secret) }
	);
	return status;
}

/**
 * @proves A sealed secret opens only in the record and field it was sealed for, and only as it was written:
 * a value moved to another application, or altered by one character, never authenticates anyone.
 */
describe('a sealed client secret changed in the database', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		seedClient(OTHER);
		await sealedSecretOf(client.clientId);
		await sealedSecretOf(OTHER.clientId);
	});

	it('a sealed value copied into another record is unreadable there', async () => {
		TestAdapter.for('Client').syncUpdate(OTHER.clientId, {
			clientSecret: await sealedSecretOf(client.clientId)
		});

		expect(await tokenStatus(OTHER.clientId, client.clientSecret)).toBe(401);
	});

	it('a sealed value with altered bytes is unreadable', async () => {
		const sealed = await sealedSecretOf(client.clientId);
		const at = sealed.length - 30;
		const altered =
			sealed.slice(0, at) +
			(sealed[at] === 'A' ? 'B' : 'A') +
			sealed.slice(at + 1);
		TestAdapter.for('Client').syncUpdate(client.clientId, {
			clientSecret: altered
		});

		expect(await tokenStatus(client.clientId, client.clientSecret)).toBe(401);
	});
});
