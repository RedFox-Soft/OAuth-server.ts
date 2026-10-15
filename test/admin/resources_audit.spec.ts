import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

/* The audit trail for protected-resource operations. */

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.example.com/mcp';
const encoded = encodeURIComponent(AUDIENCE);

async function admin() {
	const user = await createAdministrator(
		'plain',
		`auditor-${Math.random()}@x.io`
	);
	const session = await sessionFor(user);
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		userId: user._id
	};
}

async function entriesFor(action: string) {
	const page = await adminAuditStore.list({ action, limit: 50 });
	return page.entries;
}

/*
 * A bucket with an address of its own, so its administrator declares without a super administrator: at
 * the root, declaring is reserved (root_namespace.spec.ts).
 */
async function ownedBucket(userId: string, prefix: string) {
	return getBucketStore().create({
		name: `${prefix} users`,
		slug: `${prefix}-${Math.random().toString(36).slice(2)}`,
		ownerGroupId: await personalGroupId(userId)
	});
}

/**
 * @proves Declaring, amending or removing a protected resource is recorded against the actor,
 * and a refused declaration leaves no entry.
 */
describe('protected resource audit trail', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
	});

	it('records the actor, the action and the identifier for every change', async () => {
		const { cookie, userId } = await admin();
		const bucket = await ownedBucket(userId, 'audit');
		const headers = { cookie };
		const resources = api.admin.api.buckets({ id: bucket._id }).resources;

		await resources.post(
			{ identifier: AUDIENCE, name: 'Acme MCP', scopes: ['mcp:tools-basic'] },
			{ headers }
		);
		await resources({ resourceId: encoded }).patch(
			{ name: 'Acme MCP v2' },
			{ headers }
		);
		await resources({ resourceId: encoded }).delete(undefined, { headers });

		for (const action of [
			'resource.create',
			'resource.update',
			'resource.delete'
		]) {
			const entries = await entriesFor(action);
			const mine = entries.filter((e) => e.actorId === userId);
			expect(mine, action).toHaveLength(1);
			/*
			 * The target is the canonical identifier itself, not an opaque id. It has to be: after the
			 * declaration is gone there is nothing left to resolve an id against, and an audit entry naming
			 * a row that no longer exists tells a reader nothing about which audience was withdrawn.
			 */
			expect(mine[0].targetId, action).toBe(AUDIENCE);
			expect(mine[0].targetType, action).toBe('ProtectedResource');
		}
	});

	it('leaves no entry for a declaration it refused', async () => {
		const { cookie, userId } = await admin();
		const bucket = await ownedBucket(userId, 'refused');

		const res = await api.admin.api
			.buckets({ id: bucket._id })
			.resources.post(
				{ identifier: `${AUDIENCE}#tools`, name: 'x', scopes: ['a'] },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(400);
		const mine = (await entriesFor('resource.create')).filter(
			(e) => e.actorId === userId
		);
		expect(mine).toHaveLength(0);
	});

	/*
	 * What lets a tenant read its own APIs' history: every entry names the bucket and the group that owns
	 * it, so it appears in that bucket's trail and that group's, and nobody else's.
	 */
	it("files every change in the trail of the API's bucket and that bucket's group", async () => {
		const { cookie, userId } = await admin();
		const bucket = await ownedBucket(userId, 'filed');
		const headers = { cookie };
		const resources = api.admin.api.buckets({ id: bucket._id }).resources;

		await resources.post(
			{ identifier: AUDIENCE, name: 'Acme MCP', scopes: ['mcp:tools-basic'] },
			{ headers }
		);
		await resources({ resourceId: encoded }).patch(
			{ name: 'Acme MCP v2' },
			{ headers }
		);
		await resources({ resourceId: encoded }).delete(undefined, { headers });

		const { entries } = await adminAuditStore.list({
			bucket: bucket._id,
			ownerGroupIds: [bucket.ownerGroupId],
			actionPrefix: 'resource.'
		});
		expect(entries.map((e) => e.action).sort()).toEqual([
			'resource.create',
			'resource.delete',
			'resource.update'
		]);
		expect(entries.map((e) => [e.bucketId, e.ownerGroupId])).toEqual(
			entries.map(() => [bucket._id, bucket.ownerGroupId])
		);
	});
});
