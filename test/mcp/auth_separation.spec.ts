import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { routeNames } from 'lib/consts/param_list.js';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * FR-013, both directions.
 *
 * A token that administers the server must not be usable anywhere else, and a token issued for
 * something else must not administer the server. Half of this already held before the feature existed —
 * `lib/actions/userinfo.ts` refuses any token carrying an audience at all — so only the converse needed
 * writing. Both are asserted here anyway, because the boundary is a property of the pair: a later change
 * to either endpoint could open it, and a test that only covers the new half would not notice.
 */

let rpcId = 0;

async function callMcp(token?: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				...(token ? { authorization: `Bearer ${token}` } : {})
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/list',
				params: {}
			})
		})
	);
	return res.status;
}

async function callUserinfo(token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${routeNames.userinfo}`, {
			headers: { authorization: `Bearer ${token}` }
		})
	);
	return res.status;
}

async function adminAccount() {
	return getUserStore(ADMIN_BUCKET_ID).create(
		`sep-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
}

async function tokenWithAudience(audience: string | undefined) {
	const user = await adminAccount();
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	if (audience !== undefined) at.setAudience(audience);
	return { token: (await at.save()) as unknown as string, user };
}

describe('MCP audience boundary', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		ApplicationConfig['userinfo.enabled'] = true;
		await ensureAdminSeed();
	});

	it('accepts an MCP-audience token at /mcp', async () => {
		const { token } = await tokenWithAudience(MCP_RESOURCE);
		expect(await callMcp(token)).toBe(200);
	});

	it('refuses that same token at the UserInfo endpoint', async () => {
		const { token } = await tokenWithAudience(MCP_RESOURCE);
		// A token that can administer the server must buy nothing else. Held before this feature by
		// userinfo's blanket refusal of any audience; asserted here so a change there is visible.
		expect(await callUserinfo(token)).toBe(401);
	});

	it('refuses an audience-less token at /mcp', async () => {
		const { token } = await tokenWithAudience(undefined);
		// The converse, and the half this feature had to write: without it, a token minted for UserInfo
		// would administer the server — the confused-deputy problem resource indicators exist for.
		expect(await callMcp(token)).toBe(401);
	});

	it('refuses a token minted for some other resource at /mcp', async () => {
		const { token } = await tokenWithAudience('https://elsewhere.example/api');
		expect(await callMcp(token)).toBe(401);
	});

	it('refuses a token whose account is not an administrator', async () => {
		// Right audience, wrong bucket: an agent authenticated against any other bucket is not an
		// administrator, whatever its token says.
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: 'not-an-admin-account-id',
			scope: 'openid'
		});
		at.setAudience(MCP_RESOURCE);
		const token = (await at.save()) as unknown as string;
		expect(await callMcp(token)).toBe(401);
	});

	it('refuses a token whose administrator has been deactivated', async () => {
		const { token, user } = await tokenWithAudience(MCP_RESOURCE);
		expect(await callMcp(token)).toBe(200);

		await getUserStore(ADMIN_BUCKET_ID).update(user._id, { active: false });

		// Resolved per request, so a deactivation takes effect on the next call rather than at the next
		// reconnection (FR-011).
		expect(await callMcp(token)).toBe(401);
	});

	it('refuses a token that no longer exists', async () => {
		const { token } = await tokenWithAudience(MCP_RESOURCE);
		expect(await callMcp(token)).toBe(200);

		await AccessToken.adapter.destroy(token);

		// Expiry and revocation collapse into the same check: a token that is gone is not found.
		expect(await callMcp(token)).toBe(401);
	});

	it('refuses a missing credential without disclosing anything', async () => {
		const status = await callMcp();
		expect(status).toBe(401);
	});
});
