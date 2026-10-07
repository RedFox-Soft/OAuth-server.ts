import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { auditRoutes } from 'lib/admin/audit/routes.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';
import { present } from 'test/shape.js';
import { createAdministrator, type AdminKind } from '../administrators.ts';

/*
 * The tenant boundary of the audit trail.
 *
 * A group must be able to answer "who changed this, and when" about its own containers without the
 * operator, and must not be able to retrieve anything about another group by any combination of
 * filters. The second half is the one that needs testing hardest: the restriction is applied where
 * entries are selected, and a bug there answers 200 with somebody else's history.
 */
const app = new Elysia()
	.use(resolveAdmin)
	.use(auditRoutes)
	.use(groupRoutes)
	.use(projectRoutes);
const client = treaty(app);

function slug(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2)}`;
}

async function tenant(kind: AdminKind = 'plain') {
	const user = await createAdministrator(kind, `${slug('a')}@x.io`);
	const session = await sessionFor(user);
	const cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
	return { userId: user._id, cookie };
}

/**
 * @proves A project administrator reads the trail of the containers their groups own and nothing
 * else, under every filter and after the container is gone.
 */
describe('group-scoped audit read', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('shows a group its own container history', async () => {
		const a = await tenant();
		const project = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Mine', slug: slug('m') },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		const page = answered(
			(
				await client.admin.api.audit.get({
					query: { targetId: project._id },
					headers: { cookie: a.cookie }
				})
			).data
		);

		expect(page.total).toBe(1);
		expect(present(page.entries[0], 'page.entries[0]').action).toBe(
			'project.create'
		);
		expect(
			present(page.entries[0], 'page.entries[0]').ownerGroupId
		).toBeString();
	});

	it('hides another group’s history under every filter, including a direct one', async () => {
		const a = await tenant();
		const b = await tenant();

		const theirs = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Theirs', slug: slug('t') },
					{ headers: { cookie: b.cookie } }
				)
			).data
		);

		// Unfiltered.
		const all = answered(
			(
				await client.admin.api.audit.get({
					query: {},
					headers: { cookie: a.cookie }
				})
			).data
		);
		expect(JSON.stringify(all.entries)).not.toContain(theirs._id);

		// Aimed straight at the other tenant's container.
		const aimed = answered(
			(
				await client.admin.api.audit.get({
					query: { targetId: theirs._id },
					headers: { cookie: a.cookie }
				})
			).data
		);
		expect(aimed.total).toBe(0);

		// By action, which would otherwise sweep every tenant's creations.
		const byAction = answered(
			(
				await client.admin.api.audit.get({
					query: { action: 'project.create' },
					headers: { cookie: a.cookie }
				})
			).data
		);
		expect(JSON.stringify(byAction.entries)).not.toContain(theirs._id);
	});

	it('keeps instance-wide entries out of a project administrator’s reach', async () => {
		const a = await tenant();

		/*
		 * Settings, keys and administrator accounts belong to no group, so no group restriction can match
		 * them. Asserted through the action filter, which is how somebody would go looking.
		 */
		const page = answered(
			(
				await client.admin.api.audit.get({
					query: { action: 'settings.update' },
					headers: { cookie: a.cookie }
				})
			).data
		);
		expect(page.total).toBe(0);
	});

	it('still refuses a mistyped filter rather than widening the trail', async () => {
		const a = await tenant();
		const res = await client.admin.api.audit.get({
			// A filter the schema does not know. Answering it by ignoring the parameter would return a
			// wider trail than the caller asked for — a wrong answer wearing a 200.
			// @ts-expect-error an undeclared filter; the route must refuse it
			query: { ownerGroupId: 'someone-elses-group' },
			headers: { cookie: a.cookie }
		});
		expect(res.status).toBe(422);
	});

	it('keeps an entry readable after the container it describes is gone', async () => {
		const a = await tenant();
		const project = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Doomed', slug: slug('d') },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		const deleted = await client.admin.api
			.projects({ id: project._id })
			.delete(undefined, { headers: { cookie: a.cookie } });
		expect(deleted.status).toBe(200);

		const page = answered(
			(
				await client.admin.api.audit.get({
					query: { targetId: project._id },
					headers: { cookie: a.cookie }
				})
			).data
		);

		// Creation and deletion both survive: the entry carries its group, so it does not depend on the
		// container still existing to be attributed.
		expect(page.total).toBe(2);
	});

	it('serves a super administrator the whole trail', async () => {
		const su = await tenant('super');
		const a = await tenant();
		const project = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Someone else’s', slug: slug('x') },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		const page = answered(
			(
				await client.admin.api.audit.get({
					query: { targetId: project._id },
					headers: { cookie: su.cookie }
				})
			).data
		);
		expect(page.total).toBe(1);
	});
});
