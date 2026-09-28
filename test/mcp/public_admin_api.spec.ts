import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * An agent's token administers the server through `/mcp` and nowhere else. The operations withheld from
 * an agent and the confirmation asked of it for a destructive one live in that transport, so the same
 * token presented straight to the management API skipped both: an agent able to make an HTTP request —
 * one following instructions injected into data it had read, say — could delete a project, or permit
 * another client identity onto the administrative plane, with nothing but its own credential.
 */

async function agentToken() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`agent-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return at.save();
}

function direct(method: string, path: string, token: string) {
	return elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { authorization: `Bearer ${token}` }
		})
	);
}

/**
 * @proves An agent's token is refused by the management API when presented to it directly, so what
 * the agent surface withholds or gates cannot be reached around it.
 */
describe('an agent token presented directly to the management API', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'withheld' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('is accepted at the agent endpoint', async () => {
		const res = await elysia.handle(
			new Request(`http://e.ly${MCP_ROUTE}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					accept: 'application/json, text/event-stream',
					authorization: `Bearer ${await agentToken()}`
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/list',
					params: {}
				})
			})
		);

		expect(res.status).toBe(200);
	});

	it('is refused for a read', async () => {
		const res = await direct('GET', '/admin/api/projects', await agentToken());

		expect(res.status).toBe(401);
	});

	it('deletes nothing through an operation the agent surface withholds', async () => {
		const project = await getProjectStore().create({
			name: 'Kept',
			slug: `kept-${Math.random()}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		await direct(
			'DELETE',
			`/admin/api/projects/${project._id}`,
			await agentToken()
		);

		expect(await getProjectStore().find(project._id)).toBeTruthy();
	});
});
