import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { shaped } from 'test/shape.js';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	regularGroup
} from '../admin/ownership_fixtures.ts';
import { rpc } from './rpc.ts';

let rpcId = 0;

async function agentFor(user: User): Promise<string> {
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

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	projects: Type.Array(Type.Object({ id: Type.String(), name: Type.String() }))
});

/* Alice keeps a bucket with two projects in her personal group and owns Team; her agent moves it. */
async function world() {
	const alice = await createAdministrator(
		'plain',
		`agent-${Math.random()}@x.io`
	);
	const personal = await ensurePersonalGroup(alice._id, alice.email);
	const team = await regularGroup([alice]);
	const { bucket, projects } = await bucketWithProjects(personal._id, 2);
	return {
		alice,
		personal,
		team,
		bucket,
		projects,
		token: await agentFor(alice)
	};
}

/**
 * @proves An agent moves a bucket and its projects to another group only through two confirmed calls, sees
 * which projects move before it does, cannot stretch a confirmation given for the preview to the move
 * itself, and is attributed in the trail beside its administrator; it cannot share a personal group.
 */
describe('an agent moving a bucket to another group', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'confirmation' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('is asked to confirm, and nothing moves', async () => {
		const w = await world();

		const described = await rpc(
			call('bucket_owner_change', { id: w.bucket._id, groupId: w.team._id }),
			w.token
		);

		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		expect((await getBucketStore().find(w.bucket._id))?.ownerGroupId).toBe(
			w.personal._id
		);
	});

	it('sees the projects that would move when it confirms without `confirm`, and nothing moves', async () => {
		const w = await world();
		const args = { id: w.bucket._id, groupId: w.team._id };
		const described = await rpc(call('bucket_owner_change', args), w.token);

		const previewed = await rpc(
			call('bucket_owner_change', {
				...args,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			w.token
		);

		const preview = shaped(
			Preview,
			previewed.result?.structuredContent?.preview
		);
		expect(preview.projects.map((p) => p.id).sort()).toEqual(
			w.projects.map((p) => p._id).sort()
		);
		expect((await getBucketStore().find(w.bucket._id))?.ownerGroupId).toBe(
			w.personal._id
		);
	});

	it('moves the bucket with a confirmation obtained for `confirm: true`, attributed to the agent', async () => {
		const w = await world();
		const args = { id: w.bucket._id, groupId: w.team._id, confirm: true };
		const described = await rpc(call('bucket_owner_change', args), w.token);

		const performed = await rpc(
			call('bucket_owner_change', {
				...args,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			w.token
		);

		expect(performed.result?.isError).not.toBe(true);
		expect((await getBucketStore().find(w.bucket._id))?.ownerGroupId).toBe(
			w.team._id
		);
		const { entries } = await adminAuditStore.list({
			targetId: w.bucket._id,
			action: 'bucket.owner.change'
		});
		expect(entries[0]?.actorId).toBe(w.alice._id);
		expect(entries[0]?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
	});

	it('cannot move with a confirmation obtained for the preview', async () => {
		const w = await world();
		const args = { id: w.bucket._id, groupId: w.team._id };
		const described = await rpc(call('bucket_owner_change', args), w.token);

		const stretched = await rpc(
			call('bucket_owner_change', {
				...args,
				confirm: true,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			w.token
		);

		expect(stretched.result?.isError).toBe(true);
		expect((await getBucketStore().find(w.bucket._id))?.ownerGroupId).toBe(
			w.personal._id
		);
	});

	it('cannot add anyone to its administrator’s personal group', async () => {
		const w = await world();
		const colleague = await createAdministrator(
			'plain',
			`colleague-${Math.random()}@x.io`
		);

		const added = await rpc(
			call('group_member_add', {
				id: w.personal._id,
				userId: colleague._id,
				role: 'member'
			}),
			w.token
		);

		expect(added.result?.isError).toBe(true);
		expect(added.result?.structuredContent?.reason).toBe('forbidden');
	});
});
