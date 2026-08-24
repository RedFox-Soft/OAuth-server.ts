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
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * A KNOWN LIMITATION, pinned so it is a documented state rather than a latent surprise.
 *
 * A sender-constrained (DPoP-bound) token cannot be used for tool calls. A DPoP proof is bound to one
 * method and one URL — the client makes it for `POST /mcp` — and when a tool re-dispatches into an admin
 * route that request carries no proof and could not carry a valid one, because a proof for
 * `PATCH /admin/api/...` is not something the client ever created.
 *
 * So the re-dispatch finds `jkt` set with no proof and refuses. That is the safe direction: a bound token
 * is never silently accepted without proof of possession. It does mean DPoP-using clients cannot use this
 * surface while `dpop.enabled` is on, which is off by default.
 *
 * Fixing it means the re-dispatch trusting the entry point's validation, and the only safe way to express
 * that trust is a channel the network cannot reach — not a header, which `adminApp` being publicly
 * mounted would make spoofable. This spec exists so that work starts from a failing expectation rather
 * than from a bug report.
 */

let rpcId = 0;

async function callMcp(token: string) {
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
				id: ++rpcId,
				method: 'tools/list',
				params: {}
			})
		})
	);
	return res.status;
}

async function tokenFor(bound: boolean) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`dpop-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid',
		// A thumbprint is what makes a token sender-constrained; its value is immaterial here, since the
		// point is that no proof accompanies the re-dispatch.
		...(bound ? { jkt: 'a-key-thumbprint' } : {})
	});
	at.setAudience(MCP_RESOURCE);
	return (await at.save()) as unknown as string;
}

describe('sender-constrained tokens on the MCP surface', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('accepts a bearer token that is not sender-constrained', async () => {
		// The control: without this, the assertion below would pass for the wrong reason.
		expect(await callMcp(await tokenFor(false))).toBe(200);
	});

	it('refuses a DPoP-bound token presented without a proof', async () => {
		// Fails closed. A bound token is never accepted on possession the caller has not proved.
		expect(await callMcp(await tokenFor(true))).toBe(401);
	});

	it('refuses a DPoP-bound token even with DPoP switched off', async () => {
		// `dpop.enabled: false` stops the server *requiring* proofs; it does not make an already-bound
		// token safe to accept unproven, and the binding on the token still has to be honoured.
		ApplicationConfig['dpop.enabled'] = false;
		expect(await callMcp(await tokenFor(true))).toBe(401);
	});
});
