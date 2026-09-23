import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { mock } from '../fetch_mock.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getProjectStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		})
	);
	const text = await res.text();
	const line = text.split('\n').find((l) => l.startsWith('data:'));
	return line
		? JSON.parse(line.slice('data:'.length).trim())
		: JSON.parse(text);
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function agentToken() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`edit-agent-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
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
			applicationType: 'web',
			redirectUris: ['https://rp.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'public',
			registeredDynamically: true,
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
		const project = await getProjectStore().create({
			name: 'Agent edit',
			slug: `agent-edit-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProjectStore().update(project._id, {
			clientIds: [record.clientId]
		});
		const before = await adapter('Client').find(record.clientId);

		const response = await rpc(
			call('client_update', {
				id: project._id,
				clientId: record.clientId,
				clientName: 'After'
			}),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		const after = await adapter('Client').find(record.clientId);
		expect(after.client_name).toBe('After');
		for (const [name, value] of Object.entries(before)) {
			if (name === 'client_name') continue;
			expect({ [name]: after[name] }).toEqual({ [name]: value });
		}
	});

	it('is refused a redirect URI the sector identifier document of a pairwise client does not list', async () => {
		const token = await agentToken();
		const record = {
			clientId: 'agent-edit-sector',
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
		const project = await getProjectStore().create({
			name: 'Agent sector',
			slug: `agent-sector-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProjectStore().update(project._id, {
			clientIds: [record.clientId]
		});
		const before = await adapter('Client').find(record.clientId);

		const response = await rpc(
			call('client_update', {
				id: project._id,
				clientId: record.clientId,
				redirectUris: [
					'https://rp.example.com/cb',
					'https://rp.example.com/unlisted'
				]
			}),
			token
		);

		mock.restore();
		expect(response.result?.isError).toBe(true);
		expect(await adapter('Client').find(record.clientId)).toEqual(before);
	});
});
