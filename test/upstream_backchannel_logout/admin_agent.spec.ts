import { describe, it, beforeAll, beforeEach, expect } from 'bun:test';

import {
	adminAuditStore,
	getBucketStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { elysia } from 'lib/index.js';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import bootstrap from '../test_helper.js';
import { createAdministrator } from '../administrators.ts';
import { pathBucketWith } from '../global_token_revocation/helpers.js';
import { logoutProvider, uniqueOrigin } from './helpers.ts';

let rpcId = 0;

async function rpc(body: unknown, token: string): Promise<unknown> {
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
	const line = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	)
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	if (line) return JSON.parse(line.slice('data:'.length).trim());
	return text ? JSON.parse(text) : undefined;
}

/* An agent acting for a super administrator, its session initialised as an MCP client initialises one. */
async function agentSession() {
	const user = await createAdministrator('super', `bcl-${Math.random()}@x.io`);
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
	return { user, token };
}

/**
 * @proves An agent switches a provider's back-channel logout on through the very operation the console uses,
 * with the same effect and one audit entry naming the administrator it acts for (spec 073 User Story 4,
 * scenario 4; FR-019; Constitution Principle II).
 */
describe('an agent connecting a provider’s back-channel logout', () => {
	beforeAll(async () => {
		/* Named: bootstrap defaults to the directory's config, and this case needs the control plane on. */
		await bootstrap(import.meta.url, { config: 'admin_agent' });
	});

	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('switches it on through the provider update the console uses', async () => {
		const { user, token } = await agentSession();
		const bucket = await pathBucketWith([
			logoutProvider('corp', uniqueOrigin('agent'), {
				acceptsBackChannelLogout: false
			})
		]);

		await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'federation_provider_update',
					arguments: {
						id: bucket._id,
						providerId: 'corp',
						acceptsBackChannelLogout: true
					}
				}
			},
			token
		);

		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation?.[0]?.acceptsBackChannelLogout).toBe(true);
		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(
			entries.filter((entry) => entry.action === 'federation.provider.update')
		).toHaveLength(1);
	});
});
