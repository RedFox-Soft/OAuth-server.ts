import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { mock } from '../fetch_mock.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { readLogo } from 'lib/models/client/logo.js';
import { PNG } from '../consent_branding/consent_branding.config.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, adminAuditStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { createAdministrator } from '../administrators.ts';
import { rpc } from './rpc.ts';

let rpcId = 0;

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

/*
 * A change to where a client may send codes, or how it authenticates, is described first and applied only
 * with the confirmation that description returns (lib/mcp/catalogue.ts, `highWhenSets`).
 */
async function confirmed(
	name: string,
	args: Record<string, unknown>,
	token: string
) {
	const described = await rpc(call(name, args), token);
	const confirmationToken =
		described.result?.structuredContent?.confirmationToken;
	if (typeof confirmationToken !== 'string') {
		throw new Error(`expected ${name} to ask for confirmation`);
	}
	return rpc(call(name, { ...args, confirmationToken }), token);
}

async function agentToken() {
	const user = await createAdministrator(
		'super',
		`edit-agent-${Math.random()}@x.io`
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

/**
 * @proves An agent editing a client through the management surface keeps every attribute of that
 * client the edit does not name, exactly as the console does.
 */
describe('an agent editing a client', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tool_behaviours' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('keeps the attributes the console does not display when it renames a client', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-private-key',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'public',
			client_id_issued_at: 1_700_000_000,
			client_name: 'Before',
			contacts: ['ops@rp.example.com'],
			default_max_age: 600,
			id_token_signed_response_alg: 'ES256',
			jwks_uri: 'https://rp.example.com/jwks',
			require_auth_time: true,
			token_endpoint_auth_method: 'private_key_jwt'
		};
		seedClient(record);
		const before = await adapter('Client').find(record.clientId);

		const response = await rpc(
			call('client_update', {
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				clientName: 'After'
			}),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		const after = await adapter('Client').find(record.clientId);
		if (!before || !after) throw new Error('expected the stored client');
		expect(after.client_name).toBe('After');
		for (const [name, value] of Object.entries(before)) {
			if (name === 'client_name') continue;
			expect({ [name]: after[name] }).toEqual({ [name]: value });
		}
	});

	it('lets people choose permissions once an agent turns it on, recorded as the agent', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-partial',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);

		const response = await rpc(
			call('client_update', {
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				partialConsent: true
			}),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect((await Client.find(record.clientId))['consent.partial']).toBe(true);
		const { entries } = await adminAuditStore.list({
			targetId: record.clientId,
			action: 'client.update'
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]?.attributes).toEqual(['partialConsent']);
		expect(entries[0]?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
	});

	// specs/127: making an application require a code is high-consequence for an agent and previewed as for a person.
	it('holds back requiring a code until confirmed, then previews whom it reaches, then applies it', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-code',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);
		const args = {
			id: DEFAULT_BUCKET_ID,
			clientId: record.clientId,
			requireCode: true
		};

		const described = await rpc(call('client_update', args), token);
		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		const previewed = await confirmed('client_update', args, token);
		const preview = previewed.result?.structuredContent?.preview as
			{ expect?: Record<string, number> } | undefined;
		expect(preview?.expect).toHaveProperty('withoutAuthenticator');
		expect((await Client.find(record.clientId))['signIn.requireCode']).toBe(
			false
		);

		const applied = await confirmed(
			'client_update',
			{ ...args, confirm: true, expect: preview?.expect },
			token
		);

		expect(applied.result?.isError).not.toBe(true);
		expect((await Client.find(record.clientId))['signIn.requireCode']).toBe(
			true
		);
		const { entries } = await adminAuditStore.list({
			targetId: record.clientId,
			action: 'client.update'
		});
		expect(entries.at(-1)?.attributes).toEqual(['requireCode']);
		expect(entries.at(-1)?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
	});

	it('holds back a new application that requires a code, and previews it', async () => {
		const token = await agentToken();
		const args = {
			id: DEFAULT_BUCKET_ID,
			grantTypes: ['authorization_code'],
			tokenEndpointAuthMethod: 'none',
			redirectUris: ['https://new.example.com/cb'],
			requireCode: true
		};

		const described = await rpc(call('client_create', args), token);
		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		const previewed = await confirmed('client_create', args, token);
		const preview = previewed.result?.structuredContent?.preview as
			{ expect?: Record<string, number> } | undefined;

		expect(preview?.expect?.holders).toBe(0);
	});

	it('gives a client a logo, recorded as the agent and by name, and lists it without the image', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-logo',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);

		const response = await rpc(
			call('client_update', {
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				logo: PNG
			}),
			token
		);
		const listed = await rpc(
			call('client_list', { id: DEFAULT_BUCKET_ID }),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect(await readLogo(record.clientId)).toBe(PNG);
		const { entries } = await adminAuditStore.list({
			targetId: record.clientId,
			action: 'client.update'
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]?.attributes).toEqual(['logo']);
		expect(entries[0]?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
		const text = JSON.stringify(listed.result);
		expect(text).toContain('hasLogo');
		expect(text).not.toContain('data:image');
	});

	it('gives a client a primary colour, recorded as the agent and by name, and lists it', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-colour',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);

		const response = await rpc(
			call('client_update', {
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				primaryColor: '#2f7d32'
			}),
			token
		);
		const listed = await rpc(
			call('client_list', { id: DEFAULT_BUCKET_ID }),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect((await adapter('Client').find(record.clientId))?.primaryColor).toBe(
			'#2f7d32'
		);
		const { entries } = await adminAuditStore.list({
			targetId: record.clientId,
			action: 'client.update'
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]?.attributes).toEqual(['primaryColor']);
		expect(entries[0]?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
		expect(JSON.stringify(listed.result)).toContain('primaryColor');
	});

	it('is refused a redirect URI the sector identifier document of a pairwise client does not list', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-sector',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'pairwise',
			sector_identifier_uri: 'https://sector.example.com/sector.json',
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);
		for (let i = 0; i < 4; i += 1) {
			mock('https://sector.example.com')
				.intercept({ path: '/sector.json' })
				.reply(200, JSON.stringify(['https://rp.example.com/cb']), {
					headers: { 'content-type': 'application/json' }
				});
		}
		const before = await adapter('Client').find(record.clientId);

		const response = await confirmed(
			'client_update',
			{
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				redirectUris: [
					'https://rp.example.com/cb',
					'https://rp.example.com/unlisted'
				]
			},
			token
		);

		mock.restore();
		expect(response.result?.isError).toBe(true);
		expect(await adapter('Client').find(record.clientId)).toEqual(before);
	});

	it('changes nothing when it adds a redirect URI without confirming, and says what it would do', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-redirect',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);
		const before = await adapter('Client').find(record.clientId);

		const response = await rpc(
			call('client_update', {
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				redirectUris: [
					'https://rp.example.com/cb',
					'https://attacker.example/cb'
				]
			}),
			token
		);

		expect(response.result?.structuredContent?.confirmationToken).toBeString();
		expect(await adapter('Client').find(record.clientId)).toEqual(before);
	});

	it('applies a redirect URI once the change is confirmed', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-redirect-confirmed',
			bucketId: DEFAULT_BUCKET_ID,
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			token_endpoint_auth_method: 'none'
		};
		seedClient(record);

		const response = await confirmed(
			'client_update',
			{
				id: DEFAULT_BUCKET_ID,
				clientId: record.clientId,
				redirectUris: [
					'https://rp.example.com/cb',
					'https://rp.example.com/two'
				]
			},
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect((await Client.find(record.clientId)).redirectUris).toContain(
			'https://rp.example.com/two'
		);
	});
});
