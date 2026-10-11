import { describe, it, beforeAll, beforeEach, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import {
	adminAuditStore,
	getBucketGroupStore,
	getUserStore
} from 'lib/adapters/index.js';
import type { User } from 'lib/adapters/types.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import bootstrap from '../test_helper.js';
import { groupIdFor } from '../admin_session.ts';
import { plainAdministrator } from '../deprovisioning_guard/helpers.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	connect,
	provider,
	scimBucket,
	type Connected
} from '../scim/helpers.ts';
import { rpc } from '../mcp/rpc.ts';
import { shaped } from '../shape.ts';

const Expect = Type.Object({
	connectionId: Type.String(),
	managed: Type.Number(),
	foreign: Type.Number()
});

const Blocker = Type.Object({
	id: Type.String(),
	email: Type.Union([Type.String(), Type.Null()])
});

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	consequences: Type.Array(Type.String(), { minItems: 1 }),
	expect: Expect,
	blockers: Type.Array(Blocker)
});

const Refusal = Type.Object({
	error: Type.Literal('admin_error'),
	message: Type.String(),
	consequences: Type.Array(Type.String()),
	expect: Expect,
	blockers: Type.Array(Blocker),
	confirmationRequired: Type.Optional(Type.Never())
});

interface World {
	c: Connected;
	user: User;
	cookie: string;
	gid: string;
}

/* A bucket its administrator's group owns, a connection on it, and a group administrators keep. */
async function world(): Promise<World> {
	const { user, cookie } = await plainAdministrator();
	const c = await connect(
		await scimBucket([provider('corp')], {
			ownerGroupId: await groupIdFor(user)
		})
	);
	const created = await admin(
		'POST',
		`/admin/api/buckets/${c.bucket._id}/groups`,
		cookie,
		{ displayName: `Finance ${Math.random().toString(36).slice(2)}` }
	);
	expect(created.status).toBe(201);
	return { c, user, cookie, gid: String(created.json.id) };
}

/* Members of the group: people the connection manages, or, with `local`, people it does not. */
async function members(w: World, n: number, local = false): Promise<User[]> {
	const store = getUserStore(w.c.bucket._id);
	const made: User[] = [];
	for (let i = 0; i < n; i += 1) {
		const name = `${local ? 'local' : 'dir'}-${Math.random().toString(36).slice(2)}`;
		made.push(
			await store.create(
				`${name}@contoso.com`,
				'a password that is long enough',
				true,
				undefined,
				local ? {} : { provisionedBy: w.c.connection._id, userName: name }
			)
		);
	}
	const added = await admin(
		'POST',
		`/admin/api/buckets/${w.c.bucket._id}/groups/${w.gid}/members`,
		w.cookie,
		{ userIds: made.map((u) => u._id) }
	);
	expect(added.status).toBe(200);
	return made;
}

function handOver(w: World, consent: Record<string, unknown> = {}) {
	return admin(
		'POST',
		`/admin/api/buckets/${w.c.bucket._id}/groups/${w.gid}/connection`,
		w.cookie,
		{ connectionId: w.c.connection._id, ...consent }
	);
}

async function keptBy(w: World): Promise<string | undefined> {
	return (await getBucketGroupStore().find(w.gid))?.provisionedBy;
}

async function audited(w: World) {
	return (
		await adminAuditStore.list({
			targetId: w.gid,
			action: 'bucketgroup.connection.assign'
		})
	).entries;
}

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

/**
 * @proves An administrator — or their agent — handing a user group to a directory first sees what the hand-over
 * means and whom it would leave behind, cannot hand over a group holding people the directory does not manage,
 * consents to the counts shown and not to whatever they have become since, and nothing reaches the audit trail
 * until a hand-over is applied (spec 084, User Story 8, R5).
 */
describe('handing a user group to a provisioning connection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('answers what the hand-over means, with its counts, and hands nothing over without confirm', async () => {
		const w = await world();
		await members(w, 2);

		const res = await handOver(w);

		expect(res.status).toBe(409);
		const preview = shaped(Preview, res.json);
		expect(preview.expect).toEqual({
			connectionId: w.c.connection._id,
			managed: 2,
			foreign: 0
		});
		expect(preview.blockers).toEqual([]);
		expect(await keptBy(w)).toBeUndefined();
	});

	it('names the members the connection does not manage', async () => {
		const w = await world();
		await members(w, 1);
		const [local] = await members(w, 1, true);

		const res = await handOver(w);

		const preview = shaped(Preview, res.json);
		expect(preview.expect.foreign).toBe(1);
		expect(preview.blockers).toEqual([{ id: local._id, email: local.email }]);
	});

	it('refuses a confirmed hand-over while a member is someone the connection does not manage', async () => {
		const w = await world();
		await members(w, 1);
		await members(w, 1, true);
		const { expect: counts } = shaped(Preview, (await handOver(w)).json);

		const res = await handOver(w, { confirm: true, expect: counts });

		expect(res.status).toBe(409);
		const refusal = shaped(Refusal, res.json);
		expect(refusal.blockers).toHaveLength(1);
		expect(await keptBy(w)).toBeUndefined();
	});

	it('answers the fresh preview to a confirmation whose counts have changed since', async () => {
		const w = await world();
		await members(w, 1);
		const { expect: counts } = shaped(Preview, (await handOver(w)).json);
		await members(w, 1);

		const res = await handOver(w, { confirm: true, expect: counts });

		expect(res.status).toBe(409);
		expect(shaped(Preview, res.json).expect.managed).toBe(2);
		expect(await keptBy(w)).toBeUndefined();
	});

	it('answers the preview to a confirmation that carries no counts', async () => {
		const w = await world();
		await members(w, 1);

		const res = await handOver(w, { confirm: true });

		expect(res.status).toBe(409);
		expect(shaped(Preview, res.json).expect.managed).toBe(1);
		expect(await keptBy(w)).toBeUndefined();
	});

	it('hands the group over on a confirmation carrying the preview’s counts, and records it', async () => {
		const w = await world();
		await members(w, 2);
		const { expect: counts } = shaped(Preview, (await handOver(w)).json);

		const res = await handOver(w, { confirm: true, expect: counts });

		expect(res.status).toBe(200);
		expect(await keptBy(w)).toBe(w.c.connection._id);
		expect((await audited(w)).map((e) => e.actorId)).toEqual([w.user._id]);
	});

	it('records nothing for a hand-over that was only previewed, stale or refused', async () => {
		const w = await world();
		await members(w, 1);
		const { expect: counts } = shaped(Preview, (await handOver(w)).json);
		await handOver(w, { confirm: true, expect: { ...counts, managed: 9 } });
		await members(w, 1, true);
		const { expect: fresh } = shaped(Preview, (await handOver(w)).json);

		await handOver(w, { confirm: true, expect: fresh });

		expect(await audited(w)).toEqual([]);
	});

	it('shows an agent the preview as a conflict, and hands nothing over', async () => {
		const w = await world();
		await members(w, 2);
		const token = await agentFor(w.user);
		const args = {
			id: w.c.bucket._id,
			gid: w.gid,
			connectionId: w.c.connection._id
		};
		const described = await rpc(
			call('bucket_group_assign_connection', args),
			token
		);

		const previewed = await rpc(
			call('bucket_group_assign_connection', {
				...args,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			token
		);

		expect(previewed.result?.structuredContent?.reason).toBe('conflict');
		const preview = shaped(
			Preview,
			previewed.result?.structuredContent?.preview
		);
		expect(preview.expect.managed).toBe(2);
		expect(await keptBy(w)).toBeUndefined();
	});
});
