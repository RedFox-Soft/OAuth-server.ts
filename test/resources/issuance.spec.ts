import { describe, beforeAll, beforeEach, it, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';

/*
 * The token endpoint resolving a declared resource. This is the integration half of what
 * `canonical.spec.ts` covers as pure functions — Principle V asks for the HTTP layer, and the
 * matching rule only earns its keep at the point a token is or is not minted.
 */

const AUDIENCE = 'https://mcp.example.com/mcp';

const auth = {
	headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
};

async function declare(
	identifier: string,
	overrides: Partial<{
		scopes: string[];
		tokenFormat: 'jwt' | 'opaque';
		accessTokenTTL: number;
	}> = {}
) {
	return getProtectedResourceStore().create({
		_id: identifier,
		projectId: 'acme',
		name: 'Acme MCP',
		scopes: overrides.scopes ?? ['mcp:tools-basic', 'mcp:files-read'],
		tokenFormat: overrides.tokenFormat,
		accessTokenTTL: overrides.accessTokenTTL
	});
}

async function tokenFor(resource: string, scope = 'mcp:tools-basic') {
	return agent.token.post(
		{ grant_type: 'client_credentials', scope, resource },
		auth
	);
}

async function clearResources() {
	const store = getProtectedResourceStore();
	for (const resource of await store.list()) {
		await store.destroy(resource._id);
	}
}

describe('issuing tokens for a declared protected resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await clearResources();
	});

	it('refuses a resource nobody declared', async () => {
		const res = await tokenFor('https://nobody.example.com/mcp');

		expect(res.status).toBe(400);
		expect((res.error?.value as { error?: string })?.error).toBe(
			'invalid_target'
		);
	});

	it('mints a token whose audience is exactly the declared identifier', async () => {
		await declare(AUDIENCE);

		const res = await tokenFor(AUDIENCE);

		expect(res.status).toBe(200);
		expect(res.data?.scope).toBe('mcp:tools-basic');
	});

	/*
	 * The intersection, not a refusal. The specification lets an authorization server issue a subset of
	 * what was requested, and refusing instead would make a general-purpose client — which asks for
	 * everything `scopes_supported` lists — unable to obtain any token at all.
	 */
	it('issues the intersection of what was asked for and what the resource recognises', async () => {
		await declare(AUDIENCE, { scopes: ['mcp:tools-basic'] });

		const res = await tokenFor(AUDIENCE, 'mcp:tools-basic mcp:admin');

		expect(res.status).toBe(200);
		expect(res.data?.scope).toBe('mcp:tools-basic');
	});

	it('tolerates an upper-case scheme or host, which clients are told to expect', async () => {
		await declare(AUDIENCE);

		for (const requested of [
			'HTTPS://mcp.example.com/mcp',
			'https://MCP.EXAMPLE.COM/mcp',
			`${AUDIENCE}/`
		]) {
			const res = await tokenFor(requested);
			expect(res.status).toBe(200);
		}
	});

	/*
	 * The cases that matter. A prefix or subpath match would let a token minted for one resource be
	 * obtained by naming another — the confused-deputy problem resource indicators exist to close.
	 */
	it('refuses a near miss rather than resolving it to the neighbour', async () => {
		await declare(AUDIENCE);

		for (const requested of [
			'https://mcp.example.com',
			'https://mcp.example.com/mcp/tools',
			'https://mcp.example.com/mcpx',
			'http://mcp.example.com/mcp',
			'https://evil.example.com/mcp'
		]) {
			const res = await tokenFor(requested);
			expect(res.status).toBe(400);
		}
	});

	it('refuses an indicator carrying a fragment, as it always has', async () => {
		await declare(AUDIENCE);

		const res = await tokenFor(`${AUDIENCE}#tools`);

		expect(res.status).toBe(400);
	});

	/*
	 * FR-004: no restart. The store is read on every request with no memo in front of it, and this is
	 * the assertion that keeps it that way — a cache added later would fail here rather than surface as
	 * an operator reporting that a deleted resource still issues tokens.
	 */
	it('stops issuing the moment a declaration is removed', async () => {
		await declare(AUDIENCE);
		expect((await tokenFor(AUDIENCE)).status).toBe(200);

		await getProtectedResourceStore().destroy(AUDIENCE);

		const res = await tokenFor(AUDIENCE);
		expect(res.status).toBe(400);
		expect((res.error?.value as { error?: string })?.error).toBe(
			'invalid_target'
		);
	});

	/*
	 * The built-in administrative audience keeps its own descriptor. A declaration must never be able
	 * to take it over — that arm resolves first, and this is what says so.
	 */
	it('leaves the administrative MCP audience to the built-in descriptor', async () => {
		const res = await tokenFor('http://e.ly/mcp', 'openid');

		expect(res.status).toBe(200);
	});
});
