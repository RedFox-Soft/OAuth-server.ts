import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { MCP_RESOURCE, MCP_ROUTE } from 'lib/mcp/consts.ts';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import { clearPermissions, permitIdentifier } from './permissions.ts';

/*
 * The three refusals the allowlist has to make, and the one thing it must never break.
 *
 * Covers what the tasks name separately as the dynamic-registration refusal, the empty default, the
 * key-proof requirement and withdrawal — kept in one file because every case is the same question
 * asked of one resolver, and four files of near-identical setup would obscure rather than clarify.
 */

const DOC = 'https://agent.example.com/oauth/client-metadata.json';
const DCR = 'https://selfmade.example.com/c.json';

async function seedClientRecord(
	clientId: string,
	extra: Record<string, unknown> = {}
) {
	await adapter('Client').upsert(clientId, {
		clientId,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback'],
		...extra
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

async function reach(token: string) {
	const res = await elysia.handle(
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
	return res.status;
}

/**
 * @proves The permission list is default-deny, is not satisfied by self-registration, takes a
 * withdrawal effect on the next call, and is scoped to the audience it was granted for.
 */
describe('enforcing the administrative client permission list', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		await seedClientRecord(DOC);
		await seedClientRecord(DCR, { registeredDynamically: true });
	});

	/*
	 * FR-018, and the reason it is absolute rather than configurable: a dynamically registered client's
	 * identity is minted on demand by whoever asked for it, so permitting one permits whoever asks
	 * next. There is no configuration under which that is a decision an operator can meaningfully make.
	 */
	it('refuses a dynamically registered client even when it is on the list', async () => {
		await permitIdentifier(DCR);

		expect(await reach(await tokenFor(DCR))).toBe(401);
	});

	it('starts with an empty list, so nothing is permitted by default', async () => {
		expect(await reach(await tokenFor(DOC))).toBe(401);
	});

	/*
	 * The remedy an operator needs when a permitted host is taken over. Checked on every call rather
	 * than at issuance, so it does not wait for a token to expire.
	 */
	it('stops an agent on its next call once the permission is withdrawn', async () => {
		await permitIdentifier(DOC);
		const token = await tokenFor(DOC);
		expect(await reach(token)).toBe(200);

		await clearPermissions();

		expect(await reach(token)).toBe(401);
	});

	/*
	 * FR-019b. The check reads the client's declared authentication method, which is sufficient rather
	 * than approximate: a client declaring `none` could not have presented a key-proof assertion at the
	 * token endpoint.
	 */
	it('refuses a client that cannot prove possession of a published key when one is required', async () => {
		await permitIdentifier(DOC, { requireKeyProof: true });

		expect(await reach(await tokenFor(DOC))).toBe(401);
	});

	it('admits one that can', async () => {
		await seedClientRecord(DOC, {
			token_endpoint_auth_method: 'private_key_jwt',
			jwks_uri: 'https://agent.example.com/jwks.json'
		});
		await permitIdentifier(DOC, { requireKeyProof: true });

		expect(await reach(await tokenFor(DOC))).toBe(200);
	});
});

describe('signing in through a permitted identity', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
	});

	/*
	 * The other half of the permission: reaching the surface is no use if the administrator cannot sign
	 * in through the client in the first place. This is the rule `research.md` D6 refused to add
	 * without an operator decision behind it — the allowlist is that decision.
	 */
	it('routes a permitted identity naming the administrative audience to the admin bucket', async () => {
		await permitIdentifier(DOC);

		expect(await resolveBucketForRequest(DOC, MCP_RESOURCE)).toBe(
			ADMIN_BUCKET_ID
		);
	});

	it('routes it nowhere special without a permission', async () => {
		expect(await resolveBucketForRequest(DOC, MCP_RESOURCE)).toBe('redfox');
	});

	/*
	 * The parameter selects the surface; it never creates the permission. A permitted identity asking
	 * for anything else is an ordinary client.
	 */
	it('routes a permitted identity naming something else nowhere special', async () => {
		await permitIdentifier(DOC);

		expect(
			await resolveBucketForRequest(DOC, 'https://elsewhere.example.com/mcp')
		).toBe('redfox');
		expect(await resolveBucketForRequest(DOC, undefined)).toBe('redfox');
	});
});
