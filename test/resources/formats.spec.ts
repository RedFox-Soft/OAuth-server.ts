import { describe, beforeAll, beforeEach, it, expect } from 'bun:test';
import { decodeJwt } from 'jose';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';

/*
 * How a declared resource's tokens are verified, and how long they live.
 *
 * The specification mandates neither format — it asks only that a resource reject a token not
 * intended for it, "or otherwise verify that they are the intended recipient" — so the choice is the
 * resource owner's. What is *not* optional is the default: a self-contained token, because the
 * alternative obliges a reader to switch introspection on and provision credentials before their MCP
 * server can verify anything, and the ten-minute guide has no room for that.
 */

const AUDIENCE = 'https://mcp.example.com/mcp';

const auth = {
	headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
};

async function declare(overrides: {
	tokenFormat?: 'jwt' | 'opaque';
	accessTokenTTL?: number;
}) {
	return getProtectedResourceStore().create({
		_id: AUDIENCE,
		projectId: 'acme',
		name: 'Acme MCP',
		scopes: ['mcp:tools-basic'],
		...overrides
	});
}

async function token() {
	const res = await agent.token.post(
		{
			grant_type: 'client_credentials',
			scope: 'mcp:tools-basic',
			resource: AUDIENCE
		},
		auth
	);
	expect(res.status).toBe(200);
	if (!res.data) throw new Error('expected a token response');
	return res.data;
}

describe('token format and lifetime for a declared resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'resources' });
	});

	beforeEach(async () => {
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource._id);
		}
	});

	/*
	 * The default, asserted as a default: nothing is passed for `tokenFormat`. A resource owner who
	 * declares nothing gets the form their own server can verify against the published keys with no
	 * request back and no credentials — which is the whole argument for it being the default.
	 */
	it('issues a self-contained token when the owner chose nothing', async () => {
		await declare({});

		const { access_token } = await token();

		expect(access_token.split('.')).toHaveLength(3);
		const claims = decodeJwt(access_token);
		expect(claims.aud).toBe(AUDIENCE);
		expect(claims.iss).toBe('http://e.ly');
	});

	it('defaults the lifetime to fifteen minutes', async () => {
		await declare({});

		expect((await token()).expires_in).toBe(900);
	});

	it('honours a lifetime the owner raised', async () => {
		await declare({ accessTokenTTL: 3600 });

		expect((await token()).expires_in).toBe(3600);
	});

	/*
	 * The opaque arm. Its value is immediate revocation, and its cost is what this case makes
	 * visible: the resource has to ask this server, over an endpoint that is off by default and
	 * requires authentication.
	 */
	it('issues an opaque token when the owner asked for one, resolvable by introspection', async () => {
		await declare({ tokenFormat: 'opaque' });

		const { access_token } = await token();
		expect(access_token.split('.')).not.toHaveLength(3);

		const introspected = await agent.token.introspect.post(
			{ token: access_token },
			auth
		);

		expect(introspected.status).toBe(200);
		const body = introspected.data as
			{ active?: boolean; aud?: string; scope?: string } | undefined;
		expect(body?.active).toBe(true);
		expect(body?.aud).toBe(AUDIENCE);
	});

	/*
	 * Cross-audience isolation, in the form a third-party resource actually sees it. Two declarations
	 * and one token: whichever resource the token was not minted for can tell, which is the whole
	 * point of binding an audience.
	 */
	it('mints a token one declared resource can tell was not for it', async () => {
		await declare({});
		await getProtectedResourceStore().create({
			_id: 'https://other.example.com/mcp',
			projectId: 'acme',
			name: 'Other MCP',
			scopes: ['mcp:tools-basic']
		});

		const claims = decodeJwt((await token()).access_token);

		expect(claims.aud).toBe(AUDIENCE);
		expect(claims.aud).not.toBe('https://other.example.com/mcp');
	});
});
