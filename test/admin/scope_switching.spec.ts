import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from './answered.ts';

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

/**
 * @proves The active scope decides where containers are created and what is visible, is
 * re-validated every request, and never reaches another administrator personal group.
 */
describe('active scope', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('starts in the personal group and offers every group the caller belongs to', async () => {
		const a = await admin();
		const group = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		const scope = answered(
			(await client.admin.api.scope.get({ headers: { cookie: a.cookie } })).data
		);

		expect(scope.activeGroupId).toBe(await personalGroupId(a.userId));
		expect(scope.available.map((g) => g.id)).toContain(group._id);
		expect(scope.available.find((g) => g.id === group._id)?.role).toBe('owner');
	});

	it('creates into whichever scope is active, and lists only that scope', async () => {
		const a = await admin();
		const group = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		// One project in the personal scope...
		const personalProject = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Personal', slug: slug('p') },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		// ...then switch, and the next creation lands in the group without being asked again.
		const switched = await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: a.cookie } }
		);
		expect(switched.status).toBe(200);

		const groupProject = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Company', slug: slug('c') },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);
		expect(groupProject.ownerGroupId).toBe(group._id);

		const inGroup = answered(
			(await client.admin.api.projects.get({ headers: { cookie: a.cookie } }))
				.data
		);
		expect(inGroup.map((p) => p._id)).toEqual([groupProject._id]);

		// Switching back shows the other set — nothing is merged.
		await client.admin.api.scope.put(
			{ groupId: await personalGroupId(a.userId) },
			{ headers: { cookie: a.cookie } }
		);
		const inPersonal = answered(
			(await client.admin.api.projects.get({ headers: { cookie: a.cookie } }))
				.data
		);
		expect(inPersonal.map((p) => p._id)).toEqual([personalProject._id]);
	});

	it('persists the choice across requests within the session', async () => {
		const a = await admin();
		const group = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

		await client.admin.api.scope.put(
			{ groupId: group._id },
			{ headers: { cookie: a.cookie } }
		);

		const later = answered(
			(await client.admin.api.scope.get({ headers: { cookie: a.cookie } })).data
		);
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
		const group = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: a.cookie } }
				)
			).data
		);

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
		const theirs = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Theirs' },
					{ headers: { cookie: b.cookie } }
				)
			).data
		);

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
	 * A personal group is the one scope instance-wide authority does not reach. A super administrator can
	 * already read every container in it; what they may not do is point their console at somebody's own
	 * workspace and act as it — the switcher must not offer it, and the switch must refuse it even when
	 * the id is supplied by hand.
	 */
	it("never offers or accepts another administrator's personal group, even to a super administrator", async () => {
		const root = await admin(['super_admin']);
		const other = await admin();
		const theirs = await personalGroupId(other.userId);
		const shared = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: other.cookie } }
				)
			).data
		);

		const scope = answered(
			(await client.admin.api.scope.get({ headers: { cookie: root.cookie } }))
				.data
		);

		// Not a filter on personal groups as such: the super administrator's own is still there.
		expect(scope.available.map((g) => g.id)).toContain(
			await personalGroupId(root.userId)
		);
		expect(scope.available.map((g) => g.id)).not.toContain(theirs);
		// Everything else the instance holds still is, including a group they do not belong to.
		expect(scope.available.map((g) => g.id)).toContain(shared._id);
		expect(scope.available.map((g) => g.id)).toContain(UNASSIGNED_GROUP_ID);

		const denied = await client.admin.api.scope.put(
			{ groupId: theirs },
			{ headers: { cookie: root.cookie } }
		);
		expect(denied.status).toBe(403);
	});

	/*
	 * The other half of that rule: a super administrator's switch into a group they do not belong to is
	 * accepted, and has to still be the active scope on the next request. Pinned because it was not —
	 * `resolveActiveGroup` re-validated against membership alone, so the choice was taken and then
	 * discarded, and the creation below landed in the holding group while the console showed the group.
	 */
	it('keeps a super administrator in a group they do not belong to', async () => {
		const root = await admin(['super_admin']);
		const other = await admin();
		const theirs = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: other.cookie } }
				)
			).data
		);

		const switched = await client.admin.api.scope.put(
			{ groupId: theirs._id },
			{ headers: { cookie: root.cookie } }
		);
		expect(switched.status).toBe(200);

		const later = answered(
			(await client.admin.api.scope.get({ headers: { cookie: root.cookie } }))
				.data
		);
		expect(later.activeGroupId).toBe(theirs._id);

		const project = answered(
			(
				await client.admin.api.projects.post(
					{ name: 'Company', slug: slug('c') },
					{ headers: { cookie: root.cookie } }
				)
			).data
		);
		expect(project.ownerGroupId).toBe(theirs._id);
	});

	/*
	 * Which personal group is the caller's own — what decides whether the console names its owner.
	 *
	 * Both ids are read before the share, deliberately: `findPersonalFor` matches any personal group the
	 * account is a member of, so once the member has been added to somebody else's it can answer with
	 * either. That ambiguity is the reason `own` is computed from `members[0]` rather than membership.
	 */
	it("marks only the caller's own personal group as theirs", async () => {
		const owner = await admin();
		const member = await admin();
		const theirs = await personalGroupId(owner.userId);
		const mine = await personalGroupId(member.userId);
		await client.admin.api
			.groups({ id: theirs })
			.members.post(
				{ userId: member.userId, role: 'member' },
				{ headers: { cookie: owner.cookie } }
			);

		const scope = answered(
			(await client.admin.api.scope.get({ headers: { cookie: member.cookie } }))
				.data
		);

		expect(scope.available.find((g) => g.id === theirs)?.own).toBe(false);
		expect(scope.available.find((g) => g.id === mine)?.own).toBe(true);
	});

	/*
	 * The case that decides whether a revoked membership is survivable. An administrator removed from the
	 * group their console is pointed at must land somewhere usable on the very next request, not be shown
	 * a scope they cannot navigate out of.
	 */
	it('falls back to the personal group when membership of the active one is revoked', async () => {
		const owner = await admin();
		const member = await admin();
		const group = answered(
			(
				await client.admin.api.groups.post(
					{ name: 'Acme' },
					{ headers: { cookie: owner.cookie } }
				)
			).data
		);
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

		const scope = answered(
			(await client.admin.api.scope.get({ headers: { cookie: member.cookie } }))
				.data
		);
		expect(scope.activeGroupId).toBe(await personalGroupId(member.userId));
		expect(scope.available.map((g) => g.id)).not.toContain(group._id);
	});
});
