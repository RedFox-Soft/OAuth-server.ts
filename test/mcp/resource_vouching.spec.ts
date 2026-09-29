import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.ts';
import { serveResourceMetadata } from '../resources/resource_metadata.ts';

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
	return {
		raw: text,
		payload: line
			? JSON.parse(line.slice('data:'.length).trim())
			: JSON.parse(text)
	};
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function agent() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`vouch-agent-${Math.random()}@x.io`,
		'hash',
		['super_admin']
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
 * @proves An agent reads a declared resource's vouching status through the same route the console
 * uses, and receives the status rather than anything the resource published.
 */
describe('an agent checking a resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('reads whether the resource vouches for its declaration', async () => {
		const token = await agent();
		const identifier = `https://agent-vouch-${Math.random().toString(36).slice(2, 8)}.example/mcp`;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Agent vouch',
			slug: `agent-vouch-${Math.random().toString(36).slice(2)}`
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier,
			projectId: project._id,
			name: 'Agent vouch',
			scopes: ['mcp:tools-basic']
		});
		serveResourceMetadata(identifier);

		const { payload } = await rpc(
			call('resource_vouching_check', {
				id: project._id,
				resourceId: identifier
			}),
			token
		);

		assertNoPendingInterceptors();
		expect(payload.result?.structuredContent?.result).toMatchObject({
			status: 'vouched',
			step: 'path_inserted'
		});
	});
});
