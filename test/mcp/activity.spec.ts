import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getActivityStore } from 'lib/adapters/index.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import type { Group, User } from 'lib/adapters/types.ts';
import type { OverviewAnswer } from 'lib/activity/overview.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from '../admin/ownership_fixtures.ts';
import { startCounting } from '../activity/fixtures.ts';
import { call, rpc } from './rpc.ts';

let rpcId = 0;
let owner: User;
let foreigner: User;
let bucketId: string;
let customer: Group;

async function agentToken(user: User): Promise<string> {
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
	return token;
}

async function viaConsole(user: User) {
	const res = await elysia.handle(
		new Request(`http://e.ly/admin/api/buckets/${bucketId}/activity`, {
			headers: { cookie: await cookieFor(user) }
		})
	);
	return { status: res.status, body: (await res.json()) as unknown };
}

/**
 * @proves An agent reads a bucket's active users with exactly the permissions of the administrator who
 * authorized it: the numbers the console shows that administrator, and the console's refusal for a bucket
 * that is not theirs.
 */
describe('active users read by an agent', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		await startCounting();
		owner = await createAdministrator(
			'plain',
			`mcp-activity-owner-${Math.random()}@x.io`
		);
		foreigner = await createAdministrator(
			'plain',
			`mcp-activity-foreign-${Math.random()}@x.io`
		);
		customer = await regularGroup([owner]);
		bucketId = (await bucketWithProjects(customer._id, 0)).bucket._id;
		await getActivityStore().mark({
			bucketId,
			accountId: 'mcp-activity-account',
			kind: 'local',
			provisioned: false,
			at: new Date()
		});
	});

	it('gives an agent the figures the console gives its administrator', async () => {
		const token = await agentToken(owner);

		const answer = await rpc(
			call('bucket_activity_get', { id: bucketId }),
			token
		);

		const console_ = await viaConsole(owner);
		expect(console_.status).toBe(200);
		expect(answer.result?.isError).not.toBe(true);
		expect(answer.result?.structuredContent?.result).toEqual(console_.body);
	});

	it('refuses an agent a bucket its administrator cannot read, as the console does', async () => {
		const token = await agentToken(foreigner);

		const answer = await rpc(
			call('bucket_activity_get', { id: bucketId }),
			token
		);

		expect((await viaConsole(foreigner)).status).toBe(403);
		expect(answer.result?.isError).toBe(true);
		expect(answer.result?.structuredContent?.reason).toBe('forbidden');
	});

	it("gives an agent of a super administrator each bucket's customer and the customers' sums", async () => {
		const token = await agentToken(await createAdministrator('super'));

		const answer = await rpc(call('activity_overview', {}), token);

		expect(answer.result?.isError).not.toBe(true);
		const overview = answer.result?.structuredContent?.result as OverviewAnswer;
		const row = overview.buckets.find((b) => b.bucketId === bucketId);
		expect(row?.customer).toMatchObject({
			groupId: customer._id,
			label: customer.name
		});
		const summed = overview.customers.find(
			(c) => c.customer.groupId === customer._id
		);
		expect(summed).toMatchObject({
			bucketIds: [bucketId],
			contacts: [owner.email],
			current: { total: 1 }
		});
	});
});
