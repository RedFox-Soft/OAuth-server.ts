import { describe, it, beforeAll, expect } from 'bun:test';

import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import bootstrap from '../test_helper.js';
import { defaultBucket } from './fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { rpc as mcpRpc } from '../mcp/rpc.ts';

let rpcId = 0;

async function rpc(method: string, params: unknown, token: string) {
	return mcpRpc({ jsonrpc: '2.0', id: ++rpcId, method, params }, token);
}

/* An agent acting for a super administrator, as the MCP surface authenticates one. */
async function agentToken(): Promise<string> {
	await ensureAdminSeed();
	const user = await createAdministrator('super', `agent-${nanoid()}@x.io`);
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
				arguments: { id: DEFAULT_BUCKET_ID, uid: user._id, claims: {} }
			},
			token
		);

		expect(refused.result?.isError).toBe(true);
		expect(refused.result?.structuredContent?.message).toContain('conn-a');
	});
});
