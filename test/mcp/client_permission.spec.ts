import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import {
	clearPermissions,
	permitHost,
	permitIdentifier
} from './permissions.ts';

/*
 * Which client identities may reach the administrative MCP plane.
 *
 * The allowlist is what `specs/024-admin-mcp-control-plane/research.md` D6 found missing when it
 * refused to route clients to the administrator bucket on the strength of a request parameter. A
 * document identifier is a stable URL, so an operator can name exactly which ones may administer their
 * instance — the parameter no longer decides anything on its own.
 */

const DOC = 'https://agent.example.com/oauth/client-metadata.json';

async function seedDocumentClient(clientId: string) {
	/*
	 * Stored rather than served, because what is under test is the permission check and not document
	 * retrieval — `test/cimd/` covers that. A stored client whose id is a URL resolves from the adapter,
	 * which is the ordering `test/cimd/no_record.spec.ts` pins.
	 */
	await adapter('Client').upsert(clientId, {
		clientId,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	});
}

async function tokenFor(clientId: string) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`admin-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(clientId),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return (await at.save()) as unknown as string;
}

async function callMcp(token: string) {
	return elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 'test-agent', version: '1.0.0' }
				}
			})
		})
	);
}

/**
 * @proves Only client identities an operator permitted reach the administrative plane, matched
 * by exact host rather than by prefix.
 */
describe('permitting a client identity at the administrative plane', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		await seedDocumentClient(DOC);
	});

	it('admits a permitted document identifier', async () => {
		await permitIdentifier(DOC);

		const res = await callMcp(await tokenFor(DOC));

		expect(res.status).toBe(200);
	});

	/*
	 * The refusal is the surface's single indistinguishable 401 — the same answer an unknown token, a
	 * wrong audience and a deactivated account all get. Which check failed is not something an
	 * unauthenticated caller gets to probe for.
	 */
	it('refuses an identifier nobody permitted', async () => {
		const res = await callMcp(await tokenFor(DOC));

		expect(res.status).toBe(401);
		expect(res.headers.get('www-authenticate')).toContain('invalid_token');
	});

	it('admits every identifier a permitted host publishes', async () => {
		const sibling = 'https://agent.example.com/other/client.json';
		await seedDocumentClient(sibling);
		await permitHost('agent.example.com');

		expect((await callMcp(await tokenFor(DOC))).status).toBe(200);
		expect((await callMcp(await tokenFor(sibling))).status).toBe(200);
	});

	it('does not let a permitted host cover a different one', async () => {
		await seedDocumentClient('https://evil.example.com/c.json');
		await permitHost('agent.example.com');

		const res = await callMcp(
			await tokenFor('https://evil.example.com/c.json')
		);

		expect(res.status).toBe(401);
	});

	/*
	 * The reserved client keeps working exactly as documented, with no entry in the list. Its route to
	 * the administrator bucket is membership of the reserved admin project, which predates all of this.
	 */
	it('leaves the reserved administrative client unaffected', async () => {
		const res = await callMcp(await tokenFor(ADMIN_MCP_CLIENT_ID));

		expect(res.status).toBe(200);
	});
});
