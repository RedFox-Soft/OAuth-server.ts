import { describe, it, beforeAll, expect } from 'bun:test';

import { elysia } from 'lib/index.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import bootstrap from '../test_helper.js';
import { defaultBucket } from './fixtures.ts';

let rpcId = 0;

async function rpc(method: string, params: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params })
		})
	);
	const text = await res.text();
	const line = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	)
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	return JSON.parse(line ? line.slice('data:'.length).trim() : text);
}

/* An agent acting for a super administrator, as the MCP surface authenticates one. */
async function agentToken(): Promise<string> {
	await ensureAdminSeed();
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`agent-${nanoid()}@x.io`,
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
		'initialize',
		{
			protocolVersion: '2026-07-28',
			capabilities: {},
			clientInfo: { name: 'test-agent', version: '1.0.0' }
		},
		token
	);
	return token;
}

/**
 * @proves An AI agent meets the same refusal an administrator does when it edits a user a
 * provisioning connection manages — MCP has no back door (spec 069, FR-006; constitution II).
 */
describe('an AI agent acting on a user managed by a provisioning connection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'managed_users_mcp' });
	});

	it('is refused when updating the user', async () => {
		const token = await agentToken();
		const user = await createEndUser(
			await defaultBucket(),
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email: `managed-${nanoid()}@x.io` },
			async () => {}
		);

		const refused = await rpc(
			'tools/call',
			{
				name: 'bucket_user_update',
				arguments: { id: DEFAULT_BUCKET_ID, uid: user._id, roles: [] }
			},
			token
		);

		expect(refused.result?.isError).toBe(true);
		expect(refused.result?.structuredContent?.message).toContain('conn-a');
	});
});
