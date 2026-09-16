import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getProjectStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

/*
 * The audit trail for protected-resource operations, and the one cascade a project delete performs.
 *
 * Both route groups are mounted because the cascade spans them: the project route is what removes a
 * project's declarations, and the entry it writes has to say how many went.
 */

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes)
	.use(projectRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.example.com/mcp';
const encoded = encodeURIComponent(AUDIENCE);

async function admin() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`auditor-${Math.random()}@x.io`,
		'hash',
		['project_admin']
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

/**
 * @proves Declaring, amending or removing a protected resource is recorded against the actor,
 * and a refused declaration leaves no entry.
 */
describe('protected resource audit trail', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource._id);
		}
	});

	it('records the actor, the action and the identifier for every change', async () => {
		const { cookie, userId } = await admin();
		const project = await getProjectStore().create({
			name: 'Acme',
			slug: `audit-${Math.random().toString(36).slice(2)}`,
			ownerGroupId: await personalGroupId(userId)
		});
		const headers = { cookie };
		const resources = api.admin.api.projects({ id: project._id }).resources;

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
		const project = await getProjectStore().create({
			name: 'Acme',
			slug: `refused-${Math.random().toString(36).slice(2)}`,
			ownerGroupId: await personalGroupId(userId)
		});

		const res = await api.admin.api
			.projects({ id: project._id })
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
	 * A project's declarations go with it. Unlike its clients — which block the delete, because an
	 * operator can see and name them — a resource declaration is a property of the project rather than
	 * a thing living inside it, and leaving one behind would strand an audience whose owning project no
	 * longer exists.
	 */
	it('cascades a project delete onto its declarations and says how many went', async () => {
		const { cookie, userId } = await admin();
		const project = await getProjectStore().create({
			name: 'Acme',
			slug: `cascade-${Math.random().toString(36).slice(2)}`,
			ownerGroupId: await personalGroupId(userId)
		});
		const headers = { cookie };
		const resources = api.admin.api.projects({ id: project._id }).resources;

		await resources.post(
			{ identifier: AUDIENCE, name: 'One', scopes: ['mcp:tools-basic'] },
			{ headers }
		);
		await resources.post(
			{
				identifier: 'https://other.example.com/mcp',
				name: 'Two',
				scopes: ['mcp:tools-basic']
			},
			{ headers }
		);

		const deleted = await api.admin.api
			.projects({ id: project._id })
			.delete(undefined, { headers });

		expect(deleted.status).toBe(200);
		expect(
			(deleted.data as { resourcesRemoved?: number }).resourcesRemoved
		).toBe(2);
		expect(
			await getProtectedResourceStore().listByProject(project._id)
		).toEqual([]);

		/*
		 * A count on the project's own entry, and exactly one entry — not one per declaration, as this
		 * asserted until 051. The old shape argued that a bare number would not say which audiences
		 * stopped being served; the project's identity says it, because a deletion is all-or-nothing
		 * over what the project declared. What the change bought is a trail a bucket-sized deletion
		 * cannot bury.
		 */
		const mine = (await entriesFor('project.delete')).filter(
			(e) => e.actorId === userId
		);
		expect(mine.length).toBe(1);
		expect(mine[0]?.cascade).toEqual({ resources: 2 });

		expect(
			(await entriesFor('resource.delete')).filter((e) => e.actorId === userId)
		).toEqual([]);
	});
});
