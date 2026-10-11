import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia({ normalize: false }).use(resolveAdmin).use(groupRoutes);

async function send(
	method: 'GET' | 'DELETE',
	path: string,
	cookie: string
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, { method, headers: { cookie } })
	);
	return { status: response.status, body: await response.json() };
}

const Can = Type.Object({
	manageMembers: Type.Boolean(),
	invite: Type.Boolean(),
	addExisting: Type.Boolean(),
	rename: Type.Boolean(),
	delete: Type.Boolean()
});

const Named = Type.Array(
	Type.Object({ id: Type.String(), name: Type.String() })
);

const GroupRead = Type.Object({
	members: Type.Array(
		Type.Object({
			userId: Type.String(),
			role: Type.String(),
			email: Type.Union([Type.String(), Type.Null()]),
			active: Type.Boolean()
		})
	),
	owns: Type.Object({ projects: Named, buckets: Named }),
	can: Can
});

/* A team with an owner and a member, owning a bucket and the project using it. */
async function team() {
	const owner = await createAdministrator('plain');
	const member = await createAdministrator('plain');
	const group = await regularGroup([owner], [member]);
	const { bucket, projects } = await bucketWithProjects(group._id, 1);
	return { owner, member, group, bucket, project: projects[0] };
}

const NONE = {
	manageMembers: false,
	invite: false,
	addExisting: false,
	rename: false,
	delete: false
};

/**
 * @proves A group's page tells everyone who may read it who is in it by email, what it owns and what they
 * may do there — each right the one the group routes would grant — tells nothing to anyone else, and a
 * refused deletion names the projects and buckets in the way.
 */
describe("an administrator group's read", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('names every member by email, owners first, and what the group owns, to a member who is not a super administrator', async () => {
		const t = await team();

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(t.member)
		);

		expect(res.status).toBe(200);
		const read = shaped(GroupRead, res.body);
		expect(read.members.map((m) => [m.email, m.role, m.active])).toEqual([
			[t.owner.email, 'owner', true],
			[t.member.email, 'member', true]
		]);
		expect(read.owns).toEqual({
			projects: [{ id: t.project._id, name: t.project.name }],
			buckets: [{ id: t.bucket._id, name: t.bucket.name }]
		});
	});

	it('marks a deactivated member as inactive', async () => {
		const t = await team();
		await getUserStore(ADMIN_BUCKET_ID).update(t.member._id, { active: false });

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(t.owner)
		);

		const read = shaped(GroupRead, res.body);
		expect(read.members.find((m) => m.userId === t.member._id)?.active).toBe(
			false
		);
	});

	it('refuses a non-member, and names no member', async () => {
		const t = await team();
		const outsider = await createAdministrator('plain');

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(outsider)
		);

		expect(res.status).toBe(403);
		expect(JSON.stringify(res.body)).not.toContain(t.owner.email);
	});

	it('gives a plain member no right over the group', async () => {
		const t = await team();

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(t.member)
		);

		expect(shaped(GroupRead, res.body).can).toEqual(NONE);
	});

	it('gives an owner every right but choosing among all administrators', async () => {
		const t = await team();

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(t.owner)
		);

		expect(shaped(GroupRead, res.body).can).toEqual({
			manageMembers: true,
			invite: true,
			addExisting: false,
			rename: true,
			delete: true
		});
	});

	it('gives a super administrator every right over a regular group', async () => {
		const t = await team();
		const superAdmin = await createAdministrator('super');

		const res = await send(
			'GET',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(superAdmin)
		);

		expect(shaped(GroupRead, res.body).can).toEqual({
			manageMembers: true,
			invite: true,
			addExisting: true,
			rename: true,
			delete: true
		});
	});

	it('lets the owner of a personal group rename it and nothing else', async () => {
		const owner = await createAdministrator('plain');
		const personal = await ensurePersonalGroup(owner._id, owner.email);

		const res = await send(
			'GET',
			`/admin/api/groups/${personal._id}`,
			await cookieFor(owner)
		);

		expect(shaped(GroupRead, res.body).can).toEqual({ ...NONE, rename: true });
	});

	it('gives nobody, a super administrator included, any right over the System group', async () => {
		const superAdmin = await createAdministrator('super');

		const res = await send(
			'GET',
			`/admin/api/groups/${UNASSIGNED_GROUP_ID}`,
			await cookieFor(superAdmin)
		);

		expect(shaped(GroupRead, res.body).can).toEqual(NONE);
	});

	it('names the projects and buckets in the way when an owner deletes a group that still owns them', async () => {
		const t = await team();

		const res = await send(
			'DELETE',
			`/admin/api/groups/${t.group._id}`,
			await cookieFor(t.owner)
		);

		expect(res.status).toBe(409);
		expect(
			shaped(
				Type.Object({
					blockers: Type.Array(
						Type.Object({ kind: Type.String(), count: Type.Number() })
					)
				}),
				res.body
			).blockers
		).toEqual([
			{ kind: 'project', count: 1 },
			{ kind: 'bucket', count: 1 }
		]);
	});
});
