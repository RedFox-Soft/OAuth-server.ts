import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { eventBus } from 'lib/event_bus.js';
import { AccessToken } from 'lib/models/access_token.js';
import { IdToken } from 'lib/models/id_token.js';
import { ISSUER } from 'lib/configs/env.js';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { clearPermissions } from './permissions.ts';

/*
 * The refusal an operator cannot see.
 *
 * `/mcp` answers every rejection with the same 401 and `error="invalid_token"`, deliberately: a
 * distinguishable refusal would let an unauthenticated caller probe for valid tokens, admin accounts
 * and permitted clients. The reason goes to the `mcp.auth.error` channel instead, and nothing in the
 * server listens — so a deployment where authorization "succeeds" and the connection is then refused
 * has no way to learn why. These cases subscribe to that channel, which is what makes them able to
 * name the cause where an operator can only observe the symptom.
 */
function reasonOf(response: Response, captured: string[]): string {
	expect(response.status).toBe(401);
	return captured.at(-1) ?? '(no reason emitted)';
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

/* A token exactly as the OAuth flow mints one: the reserved MCP client, the MCP audience, and the
 * account of whoever signed in. */
async function tokenForAccount(accountId: string) {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return (await at.save()) as unknown as string;
}

/**
 * @proves An agent's connection to a freshly provisioned instance is refused until an administrator
 * exists there, and the reason is reported only on the channel no operator is watching.
 */
describe('connecting an agent to a freshly provisioned instance', () => {
	let captured: string[];

	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		captured = [];
		eventBus.removeAllListeners('mcp.auth.error');
		eventBus.on('mcp.auth.error', ({ reason }: { reason: string }) =>
			captured.push(reason)
		);
	});

	/*
	 * What provisioning leaves behind. `db:setup` seeds the reserved project, bucket and clients — but
	 * no person, because an administrator is created by whoever runs the first-run setup. So this is
	 * the state every new deployment is in before anybody signs in, and the state the failure was
	 * reported from.
	 */
	it('routes the reserved agent client to the administrators bucket', async () => {
		const bucketId = await resolveBucketForRequest(
			ADMIN_MCP_CLIENT_ID,
			MCP_RESOURCE
		);

		expect(bucketId).toBe(ADMIN_BUCKET_ID);
	});

	it('needs no allowlist entry for the reserved agent client', async () => {
		const operator = await getUserStore(ADMIN_BUCKET_ID).create(
			`admin-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);

		const response = await callMcp(await tokenForAccount(operator._id));

		expect(response.status).toBe(200);
	});

	/*
	 * The reproduction. A token minted for somebody who is not in the administrators bucket is refused,
	 * and `not_an_admin` is the reason — which is what an operator sees as "I authorized successfully
	 * and it still says unauthorized". The account exists and the sign-in was genuine; it is simply not
	 * an administrator of this instance.
	 */
	it('refuses a token whose account is not an administrator, reporting why only on the event channel', async () => {
		const response = await callMcp(await tokenForAccount('somebody-else'));

		expect(reasonOf(response, captured)).toBe('not_an_admin');
	});

	it('tells the caller nothing about which check failed', async () => {
		const response = await callMcp(await tokenForAccount('somebody-else'));

		expect(response.headers.get('www-authenticate')).toContain(
			'error="invalid_token"'
		);
		expect(await response.json()).toMatchObject({
			error: { message: 'authorization required' }
		});
	});

	/*
	 * The identifier a token minted for an administrator carries.
	 *
	 * The administrators bucket is served at the root: the console is a relying party on the instance's
	 * own issuer, and the bucket has no address of its own. Its slug exists only because a session
	 * cookie has to be named after something. A token claiming `<ISSUER>/admin` therefore names an
	 * issuer no metadata advertises, and a client that checks `iss` against what it discovered — which
	 * an agent client does — rejects it. From outside that is indistinguishable from "I authorized
	 * successfully and it still says unauthorized", because the sign-in genuinely succeeded and it is
	 * the token that is wrong.
	 */
	it('carries the instance issuer in a token minted for the administrators bucket', async () => {
		const operator = await getUserStore(ADMIN_BUCKET_ID).create(
			`admin-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const token = new IdToken(
			await Client.find(ADMIN_MCP_CLIENT_ID),
			{ sub: operator._id },
			await issuingBucket(ADMIN_BUCKET_ID)
		);

		const jwt = await token.issue('idtoken');
		const claims = JSON.parse(
			Buffer.from(jwt.split('.')[1], 'base64url').toString()
		);

		expect(claims.iss).toBe(ISSUER);
	});
});
