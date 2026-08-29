import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { Group, Project } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(groupRoutes)
	.use(scopeRoutes)
	.use(projectRoutes);
const client = treaty(app);

async function admin(roles: string[] = ['project_admin']) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`g-${Math.random().toString(36).slice(2)}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return {
		userId: user._id,
		email: user.email,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

async function makeGroup(cookie: string, name = 'Acme') {
	const res = await client.admin.api.groups.post(
		{ name },
		{ headers: { cookie } }
	);
	return res;
}

describe('groups API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a group with the creator as its first owner', async () => {
		const a = await admin();
		const res = await makeGroup(a.cookie);

		expect(res.status).toBe(201);
		const group = res.data as Group;
		expect(group.kind).toBe('regular');
		expect(group.members).toEqual([{ userId: a.userId, role: 'owner' }]);
	});

	it('lists the groups the caller belongs to, personal group included', async () => {
		const a = await admin();
		const created = (await makeGroup(a.cookie)).data as Group;

		const list = await client.admin.api.groups.get({
			headers: { cookie: a.cookie }
		});
		const ids = (list.data as Group[]).map((g) => g._id);
		expect(ids).toContain(created._id);
		expect(ids).toContain(await personalGroupId(a.userId));
	});

	it('hides a group from an administrator who does not belong to it', async () => {
		const a = await admin();
		const b = await admin();
		const group = (await makeGroup(a.cookie)).data as Group;

		const list = await client.admin.api.groups.get({
			headers: { cookie: b.cookie }
		});
		expect((list.data as Group[]).map((g) => g._id)).not.toContain(group._id);

		const read = await client.admin.api
			.groups({ id: group._id })
			.get({ headers: { cookie: b.cookie } });
		expect(read.status).toBe(403);
	});

	describe('membership', () => {
		it('lets an owner add a member, who then reaches what the group owns', async () => {
			const owner = await admin();
			const member = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;

			const added = await client.admin.api
				.groups({ id: group._id })
				.members.post(
					{ userId: member.userId, role: 'member' },
					{ headers: { cookie: owner.cookie } }
				);
			expect(added.status).toBe(200);

			// The owner creates a project in the group, then the member reaches it — without being named
			// on the project itself, which is the whole point of group ownership.
			await client.admin.api.scope.put(
				{ groupId: group._id },
				{ headers: { cookie: owner.cookie } }
			);
			const project = (
				await client.admin.api.projects.post(
					{ name: 'Shared', slug: `s-${Math.random().toString(36).slice(2)}` },
					{ headers: { cookie: owner.cookie } }
				)
			).data as Project;

			await client.admin.api.scope.put(
				{ groupId: group._id },
				{ headers: { cookie: member.cookie } }
			);
			const read = await client.admin.api
				.projects({ id: project._id })
				.get({ headers: { cookie: member.cookie } });
			expect(read.status).toBe(200);
		});

		it('refuses a plain member every membership change', async () => {
			const owner = await admin();
			const member = await admin();
			const third = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;
			await client.admin.api
				.groups({ id: group._id })
				.members.post(
					{ userId: member.userId, role: 'member' },
					{ headers: { cookie: owner.cookie } }
				);

			const add = await client.admin.api
				.groups({ id: group._id })
				.members.post(
					{ userId: third.userId, role: 'member' },
					{ headers: { cookie: member.cookie } }
				);
			expect(add.status).toBe(403);

			const promoteSelf = await client.admin.api
				.groups({ id: group._id })
				.members({ userId: member.userId })
				.patch({ role: 'owner' }, { headers: { cookie: member.cookie } });
			expect(promoteSelf.status).toBe(403);

			const evictOwner = await client.admin.api
				.groups({ id: group._id })
				.members({ userId: owner.userId })
				.delete(undefined, { headers: { cookie: member.cookie } });
			expect(evictOwner.status).toBe(403);
		});

		it('ends a removed member’s access on their very next request', async () => {
			const owner = await admin();
			const member = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;
			await client.admin.api
				.groups({ id: group._id })
				.members.post(
					{ userId: member.userId, role: 'member' },
					{ headers: { cookie: owner.cookie } }
				);

			const before = await client.admin.api
				.groups({ id: group._id })
				.get({ headers: { cookie: member.cookie } });
			expect(before.status).toBe(200);

			await client.admin.api
				.groups({ id: group._id })
				.members({ userId: member.userId })
				.delete(undefined, { headers: { cookie: owner.cookie } });

			// No re-login, no session flush: the next request resolves the new membership.
			const after = await client.admin.api
				.groups({ id: group._id })
				.get({ headers: { cookie: member.cookie } });
			expect(after.status).toBe(403);
		});

		it('never leaves a group without an owner', async () => {
			const owner = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;

			const demote = await client.admin.api
				.groups({ id: group._id })
				.members({ userId: owner.userId })
				.patch({ role: 'member' }, { headers: { cookie: owner.cookie } });
			expect(demote.status).toBe(409);

			const remove = await client.admin.api
				.groups({ id: group._id })
				.members({ userId: owner.userId })
				.delete(undefined, { headers: { cookie: owner.cookie } });
			expect(remove.status).toBe(409);
		});
	});

	/*
	 * FR-005. A personal group is an ordinary group in every respect except that it cannot be deleted
	 * and cannot lose its own administrator — which is what makes "share the thing I made on my own"
	 * an addition rather than a transfer between two kinds of owner.
	 */
	describe('a personal group is shareable', () => {
		it('gains a member, who then reaches what it owns', async () => {
			const a = await admin();
			const colleague = await admin();
			const personal = await personalGroupId(a.userId);

			const added = await client.admin.api
				.groups({ id: personal })
				.members.post(
					{ userId: colleague.userId, role: 'member' },
					{ headers: { cookie: a.cookie } }
				);
			expect(added.status).toBe(200);

			const read = await client.admin.api
				.groups({ id: personal })
				.get({ headers: { cookie: colleague.cookie } });
			expect(read.status).toBe(200);
		});

		it('never loses its own administrator, even once somebody else owns it too', async () => {
			const a = await admin();
			const colleague = await admin();
			const personal = await personalGroupId(a.userId);
			await client.admin.api
				.groups({ id: personal })
				.members.post(
					{ userId: colleague.userId, role: 'owner' },
					{ headers: { cookie: a.cookie } }
				);

			// A second owner exists, so the last-owner rule would not catch either of these.
			const removed = await client.admin.api
				.groups({ id: personal })
				.members({ userId: a.userId })
				.delete(undefined, { headers: { cookie: colleague.cookie } });
			expect(removed.status).toBe(409);

			const demoted = await client.admin.api
				.groups({ id: personal })
				.members({ userId: a.userId })
				.patch({ role: 'member' }, { headers: { cookie: colleague.cookie } });
			expect(demoted.status).toBe(409);
		});

		it('is still never deletable', async () => {
			const a = await admin();
			const res = await client.admin.api
				.groups({ id: await personalGroupId(a.userId) })
				.delete(undefined, { headers: { cookie: a.cookie } });
			expect(res.status).toBe(403);
		});
	});

	describe('deletion', () => {
		it('deletes an empty group, but only for an owner', async () => {
			const owner = await admin();
			const member = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;
			await client.admin.api
				.groups({ id: group._id })
				.members.post(
					{ userId: member.userId, role: 'member' },
					{ headers: { cookie: owner.cookie } }
				);

			const byMember = await client.admin.api
				.groups({ id: group._id })
				.delete(undefined, { headers: { cookie: member.cookie } });
			expect(byMember.status).toBe(403);

			const byOwner = await client.admin.api
				.groups({ id: group._id })
				.delete(undefined, { headers: { cookie: owner.cookie } });
			expect(byOwner.status).toBe(200);
		});

		it('refuses while the group still owns a project, and names what', async () => {
			const owner = await admin();
			const group = (await makeGroup(owner.cookie)).data as Group;
			await client.admin.api.scope.put(
				{ groupId: group._id },
				{ headers: { cookie: owner.cookie } }
			);
			await client.admin.api.projects.post(
				{ name: 'Held', slug: `h-${Math.random().toString(36).slice(2)}` },
				{ headers: { cookie: owner.cookie } }
			);

			const res = await client.admin.api
				.groups({ id: group._id })
				.delete(undefined, { headers: { cookie: owner.cookie } });
			expect(res.status).toBe(409);
		});

		it('never deletes a personal group', async () => {
			const a = await admin();
			const personal = await personalGroupId(a.userId);

			const res = await client.admin.api
				.groups({ id: personal })
				.delete(undefined, { headers: { cookie: a.cookie } });
			expect(res.status).toBe(403);
		});
	});
});
