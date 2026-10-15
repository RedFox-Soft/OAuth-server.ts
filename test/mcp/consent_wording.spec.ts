import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
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

async function agentToken() {
	const user = await createAdministrator(
		'super',
		`wording-agent-${Math.random()}@x.io`
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
	return { token, userId: user._id };
}

/**
 * @proves An agent can do what an administrator does to make the consent page speak plainly — describe a
 * service's scopes and name a bucket for its people — and each change is recorded against the
 * administrator who authorized the agent, through the agent.
 */
describe('an agent wording the consent page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tool_behaviours' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('describes the scopes of a resource it declares, and the change is attributed to it', async () => {
		const { token, userId } = await agentToken();
		const project = await getProjectStore().create({
			bucketId: DEFAULT_BUCKET_ID,
			name: 'Agent wording',
			slug: `agent-wording-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const identifier = `https://wording-${Math.floor(Math.random() * 1e6)}.example.com/mcp`;

		const response = await rpc(
			call('resource_declare', {
				id: project._id,
				identifier,
				name: 'Worded MCP',
				scopes: ['tools:call'],
				scopeDescriptions: {
					'tools:call': { description: 'run the service’s tools as you' }
				}
			}),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		const stored = await getProtectedResourceStore().find(
			ROOT_NAMESPACE,
			identifier
		);
		expect(stored?.scopeDescriptions).toEqual({
			'tools:call': { description: 'run the service’s tools as you' }
		});
		const { entries } = await adminAuditStore.list({
			action: 'resource.create',
			targetId: identifier
		});
		expect(entries[0]).toMatchObject({
			actorId: userId,
			viaClientId: ADMIN_MCP_CLIENT_ID
		});
	});

	it('names a bucket for its people, and the change is attributed to it', async () => {
		const { token, userId } = await agentToken();

		const response = await rpc(
			call('bucket_update', { id: DEFAULT_BUCKET_ID, displayName: 'Acme ID' }),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect((await getBucketStore().find(DEFAULT_BUCKET_ID))?.displayName).toBe(
			'Acme ID'
		);
		const { entries } = await adminAuditStore.list({
			action: 'bucket.update',
			targetId: DEFAULT_BUCKET_ID
		});
		const mine = entries.find((e) => e.actorId === userId);
		expect(mine).toMatchObject({ viaClientId: ADMIN_MCP_CLIENT_ID });
		expect(mine?.attributes).toContain('displayName');
	});
});
