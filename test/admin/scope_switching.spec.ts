import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { Group, Project } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(groupRoutes)
	.use(scopeRoutes)
	.use(projectRoutes);
const client = treaty(app);

function slug(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2)}`;
}

async function admin(roles: string[] = ['project_admin']) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${slug('s')}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return {
		userId: user._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

type ScopeView = {
	activeGroupId: string;
	available: { id: string; name: string; kind: string; role: string | null }[];
};

describe('active scope', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('starts in the personal group and offers every group the caller belongs to', async () => {
		const a = await admin();
		const group = (
			await client.admin.api.groups.post(
				{ name: 'Acme' },
				{ headers: { cookie: a.cookie } }
			)
		).data as Group;

		const scope = (
			await client.admin.api.scope.get({ headers: { cookie: a.cookie } })
		).data as ScopeView;

		expect(scope.activeGroupId).toBe(await personalGroupId(a.userId));
		expect(scope.available.map((g) => g.id)).toContain(group._id);
		expect(scope.available.find((g) => g.id === group._id)?.role).toBe('owner');
	});

	it('creates into whichever scope is active, and lists only that scope', async () => {
		const a = await admin();
		const group = (
			await client.admin.api.groups.post(
				{ name: 'Acme' },
				{ headers: { cookie: a.cookie } }
			)
		).data as Group;

		// One project in the personal scope...
		const personalProject = (
			await client.admin.api.projects.post(
				{ name: 'Personal', slug: slug('p') },
				{ headers: { cookie: a.cookie } }
			)
		).data as Project;

		// ...then switch, and the next creation lands in the group without being asked again.
		const switched = await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: a.cookie } }
		);
		expect(switched.status).toBe(200);

		const groupProject = (
			await client.admin.api.projects.post(
				{ name: 'Company', slug: slug('c') },
				{ headers: { cookie: a.cookie } }
			)
		).data as Project;
		expect(groupProject.ownerGroupId).toBe(group._id);

		const inGroup = (
			await client.admin.api.projects.get({ headers: { cookie: a.cookie } })
		).data as Project[];
		expect(inGroup.map((p) => p._id)).toEqual([groupProject._id]);

		// Switching back shows the other set — nothing is merged.
		await client.admin.api.scope.put(
			{ groupId: await personalGroupId(a.userId) },
			{ headers: { cookie: a.cookie } }
		);
		const inPersonal = (
			await client.admin.api.projects.get({ headers: { cookie: a.cookie } })
		).data as Project[];
		expect(inPersonal.map((p) => p._id)).toEqual([personalProject._id]);
	});

	it('persists the choice across requests within the session', async () => {
		const a = await admin();
		const group = (
			await client.admin.api.groups.post(
				{ name: 'Acme' },
				{ headers: { cookie: a.cookie } }
			)
		).data as Group;

		await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: a.cookie } }
		);

		const later = (
			await client.admin.api.scope.get({ headers: { cookie: a.cookie } })
		).data as ScopeView;
		expect(later.activeGroupId).toBe(group._id);
	});

	/*
	 * Pinned as a negative because the decision is the kind that gets quietly reversed: `PUT
	 * /admin/api/scope` is one of the two routes `excludedAdminRoutes` names, and re-adding a
	 * `recordAdminAudit` call to the handler must fail here rather than only widen the trail. The switch
	 * changes the session and nothing else, and grants no access to record — which scope a change was
	 * made from is carried by `ownerGroupId` on that change's own entry.
	 *
	 * Scoped to the destination group's id rather than a total, because `group.create` above legitimately
	 * writes an entry against that same id: the assertion is that *switching* added nothing to it.
	 */
	it('writes no audit entry for the switch itself', async () => {
		const a = await admin();
		const group = (
			await client.admin.api.groups.post(
				{ name: 'Acme' },
				{ headers: { cookie: a.cookie } }
			)
		).data as Group;

		const before = (await adminAuditStore.list({ targetId: group._id })).total;

		await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: a.cookie } }
		);

		const after = await adminAuditStore.list({ targetId: group._id });
		expect(after.total).toBe(before);
		expect(after.entries.map((e) => e.action)).not.toContain('scope.switch');
	});

	it('refuses a switch to a group the caller does not belong to', async () => {
		const a = await admin();
		const b = await admin();
		const theirs = (
			await client.admin.api.groups.post(
				{ name: 'Theirs' },
				{ headers: { cookie: b.cookie } }
			)
		).data as Group;

		const denied = await client.admin.api.scope.put(
			{ groupId: theirs._id },
			{ headers: { cookie: a.cookie } }
		);
		expect(denied.status).toBe(403);

		const invented = await client.admin.api.scope.put(
			{ groupId: 'no-such-group' },
			{ headers: { cookie: a.cookie } }
		);
		// Identical to the refusal above: a switch must not reveal which group ids are real.
		expect(invented.status).toBe(403);
	});

	/*
	 * The case that decides whether a revoked membership is survivable. An administrator removed from the
	 * group their console is pointed at must land somewhere usable on the very next request, not be shown
	 * a scope they cannot navigate out of.
	 */
	it('falls back to the personal group when membership of the active one is revoked', async () => {
		const owner = await admin();
		const member = await admin();
		const group = (
			await client.admin.api.groups.post(
				{ name: 'Acme' },
				{ headers: { cookie: owner.cookie } }
			)
		).data as Group;
		await client.admin.api
			.groups({ id: group._id })
			.members.post(
				{ userId: member.userId, role: 'member' },
				{ headers: { cookie: owner.cookie } }
			);
		await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: member.cookie } }
		);

		await client.admin.api
			.groups({ id: group._id })
			.members({ userId: member.userId })
			.delete(undefined, { headers: { cookie: owner.cookie } });

		const scope = (
			await client.admin.api.scope.get({ headers: { cookie: member.cookie } })
		).data as ScopeView;
		expect(scope.activeGroupId).toBe(await personalGroupId(member.userId));
		expect(scope.available.map((g) => g.id)).not.toContain(group._id);
	});
});
