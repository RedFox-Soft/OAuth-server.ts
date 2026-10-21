import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';

import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { elysia } from 'lib/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { shaped } from 'test/shape.js';
import { Type } from '@sinclair/typebox';

const Tokens = Type.Object({
	access_token: Type.String(),
	refresh_token: Type.Optional(Type.String())
});

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
	return res;
}

/* What the challenge tells a client to ask for — the scope an MCP client then requests. */
async function advertisedScope(): Promise<string> {
	const challenge = (await callMcp()).headers.get('www-authenticate') ?? '';
	const scope = /scope="([^"]*)"/.exec(challenge)?.[1];
	if (scope === undefined) throw new Error(`no scope in ${challenge}`);
	return scope;
}

/**
 * @proves An agent an administrator connected in the same browser as the console stays connected after
 * the administrator signs out of the console, because it asks for the access that outlives a sign-out.
 */
describe('signing out of the console', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	it('leaves an agent connected through the advertised scope working', async () => {
		const scope = await advertisedScope();
		const accountId = `admin-${++rpcId}`;
		const cookie = await setup.login({
			bucketId: ADMIN_BUCKET_ID,
			accountId,
			scope,
			resources: { [MCP_RESOURCE]: 'openid' }
		});
		await grantSuperAdmin(accountId);

		// As the MCP SDK builds it: the advertised scope, the resource, and prompt=consent with offline_access.
		const request = new AuthorizationRequest({
			client_id: ADMIN_MCP_CLIENT_ID,
			scope,
			resource: [MCP_RESOURCE],
			...(scope.split(' ').includes('offline_access')
				? { prompt: 'consent' }
				: {})
		});
		const auth = await request.authorize({ headers: { cookie } });
		// The SDK names the resource at the token endpoint too (RFC 8707 §2.2).
		const { data } = await agent.token.post({
			grant_type: 'authorization_code',
			client_id: ADMIN_MCP_CLIENT_ID,
			code: redirectParameter(auth, 'code'),
			code_verifier: request.code_verifier,
			redirect_uri: request.params.redirect_uri,
			resource: MCP_RESOURCE
		});
		const tokens = shaped(Tokens, data);
		expect((await callMcp(tokens.access_token)).status).toBe(200);

		const logout = await agent.admin.api.logout.post(undefined, {
			headers: { cookie, origin: 'http://e.ly' }
		});
		expect(logout.status).toBe(200);

		expect((await callMcp(tokens.access_token)).status).toBe(200);
		expect(tokens.refresh_token).toBeString();
	});
});
