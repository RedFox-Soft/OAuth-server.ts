import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type, type TSchema, type Static } from '@sinclair/typebox';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	getBucketStore,
	getGroupStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	DEFAULT_BUCKET_ID,
	SUPER_ADMINS_GROUP_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(bucketRoutes)
	.use(projectRoutes)
	.use(scopeRoutes);

async function call(
	method: string,
	path: string,
	cookie: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	const json = response.headers.get('content-type')?.includes('json');
	return {
		status: response.status,
		body: json && text ? (JSON.parse(text) as unknown) : text
	};
}

function as<T extends TSchema>(schema: T, value: unknown): Static<T> {
	return shaped(schema, value);
}

const Refusal = Type.Object({ error: Type.String(), message: Type.String() });
const GroupRef = Type.Object({
	id: Type.String(),
	kind: Type.Union([Type.String(), Type.Null()]),
	name: Type.Union([Type.String(), Type.Null()])
});
const Named = Type.Object({ id: Type.String(), name: Type.String() });
const BucketPreview = Type.Object({
	confirmationRequired: Type.Literal(true),
	from: GroupRef,
	to: GroupRef,
	bucket: Named,
	projects: Type.Array(Named),
	consequence: Type.String()
});
const BucketMoved = Type.Object({
	bucket: Type.Object({ id: Type.String(), ownerGroupId: Type.String() }),
	projects: Type.Array(Named)
});
const ProjectPreview = Type.Object({
	confirmationRequired: Type.Literal(true),
	from: GroupRef,
	to: GroupRef,
	project: Named,
	consequence: Type.String()
});
const Listed = Type.Array(Type.Object({ _id: Type.String() }));

function admin(kind: AdminKind = 'plain'): Promise<User> {
	return createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
}

const moveBucket = (
	cookie: string,
	id: string,
	body: Record<string, unknown>
) => call('PUT', `/admin/api/buckets/${id}/owner`, cookie, body);

const moveProject = (
	cookie: string,
	id: string,
	body: Record<string, unknown>
) => call('PUT', `/admin/api/projects/${id}/owner`, cookie, body);

async function ownerOfBucket(id: string) {
	return (await getBucketStore().find(id))?.ownerGroupId;
}

async function ownerOfProject(id: string) {
	return (await getProjectStore().find(id))?.ownerGroupId;
}

/*
 * Alice keeps a bucket with two projects in her personal group and owns Team, where Bob is a plain member.
 * Carol belongs to Alice's... nothing: a stranger to both groups.
 */
async function world() {
	const alice = await admin();
	const bob = await admin();
	const carol = await admin();
	const personal = await ensurePersonalGroup(alice._id, alice.email);
	const team = await regularGroup([alice], [bob]);
	const { bucket, projects } = await bucketWithProjects(personal._id, 2);
	return {
		alice,
		bob,
		carol,
		personal,
		team,
		bucket,
		projects,
		aliceCookie: await cookieFor(alice),
		bobCookie: await cookieFor(bob),
		carolCookie: await cookieFor(carol)
	};
}

/**
 * @proves A bucket moves to another administrator group with every project that uses it, only for an owner
 * of the group it leaves who belongs to the group it joins; a project with no bucket moves alone; every
 * refusal changes nothing and reveals nothing about what the caller cannot see.
 */
describe('moving a bucket to another group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('gives the destination the bucket and every project using it after the source’s owner confirms', async () => {
		const w = await world();

		const { status, body } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(
			as(BucketMoved, body)
				.projects.map((p) => p.id)
				.sort()
		).toEqual(w.projects.map((p) => p._id).sort());
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.team._id);
		for (const p of w.projects) {
			expect(await ownerOfProject(p._id)).toBe(w.team._id);
		}
	});

	it('moves a bucket for an owner of the source who is a plain member of the destination', async () => {
		const w = await world();
		const other = await regularGroup([w.bob], [w.alice]);

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: other._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(await ownerOfBucket(w.bucket._id)).toBe(other._id);
	});

	it('lists the moved bucket and its projects to the destination’s members', async () => {
		const w = await world();
		await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});
		await call('PUT', '/admin/api/scope', w.bobCookie, {
			groupId: w.team._id
		});

		const buckets = as(
			Listed,
			(await call('GET', '/admin/api/buckets', w.bobCookie)).body
		);
		const projects = as(
			Listed,
			(await call('GET', '/admin/api/projects', w.bobCookie)).body
		);

		expect(buckets.map((b) => b._id)).toContain(w.bucket._id);
		expect(projects.map((p) => p._id).sort()).toEqual(
			w.projects.map((p) => p._id).sort()
		);
	});

	it('refuses a member of only the source the moved bucket as it refuses one that does not exist', async () => {
		const w = await world();
		const team2 = await regularGroup([w.carol]);
		await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});
		// Carol now shares Alice's former source group only: a team Alice moved nothing into.
		await getGroupStore().update(team2._id, {
			members: [
				{ userId: w.carol._id, role: 'owner' },
				{ userId: w.alice._id, role: 'member' }
			]
		});

		const moved = await call(
			'GET',
			`/admin/api/buckets/${w.bucket._id}`,
			w.carolCookie
		);
		const missing = await call(
			'GET',
			'/admin/api/buckets/no-such-bucket',
			w.carolCookie
		);

		expect(moved.status).toBe(missing.status);
		expect(as(Refusal, moved.body).message).toBe(
			as(Refusal, missing.body).message
		);
	});

	it('refuses the source’s former members the moved projects', async () => {
		const owner = await admin();
		const colleague = await admin();
		const source = await regularGroup([owner], [colleague]);
		const target = await regularGroup([owner]);
		const { bucket, projects } = await bucketWithProjects(source._id, 1);
		await moveBucket(await cookieFor(owner), bucket._id, {
			groupId: target._id,
			confirm: true
		});
		const project = projects[0]?._id ?? '';

		const moved = await call(
			'GET',
			`/admin/api/projects/${project}`,
			await cookieFor(colleague)
		);
		const missing = await call(
			'GET',
			'/admin/api/projects/no-such-project',
			await cookieFor(colleague)
		);

		expect(moved.status).toBe(missing.status);
		expect(as(Refusal, moved.body).message).toBe(
			as(Refusal, missing.body).message
		);
	});

	it('refuses a plain member of the source, and moves nothing', async () => {
		const w = await world();
		const { bucket } = await bucketWithProjects(w.team._id, 1);
		const bobs = await ensurePersonalGroup(w.bob._id, w.bob.email);

		const { status } = await moveBucket(w.bobCookie, bucket._id, {
			groupId: bobs._id,
			confirm: true
		});

		expect(status).toBe(403);
		expect(await ownerOfBucket(bucket._id)).toBe(w.team._id);
	});

	it('refuses a destination the caller does not belong to as it refuses an unknown group', async () => {
		const w = await world();
		const strangers = await regularGroup([w.carol]);

		const foreign = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: strangers._id,
			confirm: true
		});
		const unknown = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: 'no-such-group',
			confirm: true
		});

		expect(foreign.status).toBe(unknown.status);
		expect(as(Refusal, foreign.body).message).toBe(
			as(Refusal, unknown.body).message
		);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.personal._id);
	});

	it('refuses the administrators’ bucket', async () => {
		const owner = await admin('super');

		const { status } = await moveBucket(
			await cookieFor(owner),
			ADMIN_BUCKET_ID,
			{
				groupId: UNASSIGNED_GROUP_ID,
				confirm: true
			}
		);

		expect(status).toBe(403);
	});

	it('refuses the default bucket every tenant shares', async () => {
		const superAdmin = await admin('super');
		const team = await regularGroup([superAdmin]);

		const { status } = await moveBucket(
			await cookieFor(superAdmin),
			DEFAULT_BUCKET_ID,
			{ groupId: team._id, confirm: true }
		);

		expect(status).toBe(403);
		expect(await ownerOfBucket(DEFAULT_BUCKET_ID)).not.toBe(team._id);
	});

	it('previews the bucket and its projects by name without confirmation, and moves nothing', async () => {
		const w = await world();

		const { status, body } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id
		});

		expect(status).toBe(409);
		const preview = as(BucketPreview, body);
		expect(preview.from).toEqual({
			id: w.personal._id,
			kind: 'personal',
			name: w.personal.name
		});
		expect(preview.to.id).toBe(w.team._id);
		expect(preview.bucket).toEqual({ id: w.bucket._id, name: w.bucket.name });
		expect(preview.projects.map((p) => p.name).sort()).toEqual(
			w.projects.map((p) => p.name).sort()
		);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.personal._id);
	});

	it('refuses moving into the group that already owns it', async () => {
		const w = await world();

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.personal._id,
			confirm: true
		});

		expect(status).toBe(409);
	});

	it('completes a move left part-done when it is repeated', async () => {
		const w = await world();
		await getBucketStore().update(w.bucket._id, { ownerGroupId: w.team._id });
		await getProjectStore().update(w.projects[0]?._id ?? '', {
			ownerGroupId: w.team._id
		});

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(await ownerOfProject(w.projects[1]?._id ?? '')).toBe(w.team._id);
	});

	it('refuses a bucket whose projects are in two groups other than the destination, naming neither', async () => {
		const w = await world();
		const elsewhere = await regularGroup([w.alice]);
		await getProjectStore().update(w.projects[0]?._id ?? '', {
			ownerGroupId: elsewhere._id
		});

		const { status, body } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});

		expect(status).toBe(409);
		const message = as(Refusal, body).message;
		expect(message).not.toContain(elsewhere._id);
		expect(message).not.toContain(w.personal._id);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.personal._id);
	});

	it('repairs a bucket by moving it into the group of its one mismatched project', async () => {
		const w = await world();
		await getProjectStore().update(w.projects[0]?._id ?? '', {
			ownerGroupId: w.team._id
		});

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.team._id);
		expect(await ownerOfProject(w.projects[1]?._id ?? '')).toBe(w.team._id);
	});

	it('refuses binding a source-group project to a bucket that has just moved', async () => {
		const w = await world();
		const loose = await getProjectStore().create({
			name: 'loose',
			slug: `loose-${Math.random().toString(36).slice(2)}`,
			ownerGroupId: w.personal._id
		});
		await moveBucket(w.aliceCookie, w.bucket._id, {
			groupId: w.team._id,
			confirm: true
		});

		const { status } = await call(
			'PUT',
			`/admin/api/projects/${loose._id}/bucket`,
			w.aliceCookie,
			{ bucketId: w.bucket._id }
		);

		expect(status).toBe(409);
		expect((await getProjectStore().find(loose._id))?.bucketId).toBeNull();
	});

	describe('as a super administrator', () => {
		it('moves a bucket out of the System group into a regular group', async () => {
			const superAdmin = await admin('super');
			const member = await admin();
			const team = await regularGroup([member]);
			const { bucket } = await bucketWithProjects(UNASSIGNED_GROUP_ID, 1);

			const { status } = await moveBucket(
				await cookieFor(superAdmin),
				bucket._id,
				{
					groupId: team._id,
					confirm: true
				}
			);

			expect(status).toBe(200);
			const listed = as(
				Listed,
				(await call('GET', '/admin/api/buckets', await cookieFor(member))).body
			);
			// A plain member's console is scoped to their personal group; switching shows the team's.
			expect(listed.map((b) => b._id)).not.toContain(bucket._id);
			const cookie = await cookieFor(member);
			await call('PUT', '/admin/api/scope', cookie, { groupId: team._id });
			expect(
				as(Listed, (await call('GET', '/admin/api/buckets', cookie)).body).map(
					(b) => b._id
				)
			).toContain(bucket._id);
		});

		it('moves a bucket out of an administrator’s personal group into a regular group', async () => {
			const superAdmin = await admin('super');
			const w = await world();

			const { status } = await moveBucket(
				await cookieFor(superAdmin),
				w.bucket._id,
				{ groupId: w.team._id, confirm: true }
			);

			expect(status).toBe(200);
			expect(await ownerOfBucket(w.bucket._id)).toBe(w.team._id);
		});

		it('refuses another administrator’s personal group as the destination', async () => {
			const superAdmin = await admin('super');
			const w = await world();
			const bobs = await ensurePersonalGroup(w.bob._id, w.bob.email);

			const { status, body } = await moveBucket(
				await cookieFor(superAdmin),
				w.bucket._id,
				{ groupId: bobs._id, confirm: true }
			);

			expect(status).toBe(403);
			expect(as(Refusal, body).message).toBe(
				'a personal group belongs to its administrator'
			);
		});

		it('refuses the Super administrators group as it refuses an unknown group', async () => {
			const superAdmin = await admin('super');
			const cookie = await cookieFor(superAdmin);
			const w = await world();

			const reserved = await moveBucket(cookie, w.bucket._id, {
				groupId: SUPER_ADMINS_GROUP_ID,
				confirm: true
			});
			const unknown = await moveBucket(cookie, w.bucket._id, {
				groupId: 'no-such-group',
				confirm: true
			});

			expect(reserved.status).toBe(unknown.status);
			expect(as(Refusal, reserved.body).message).toBe(
				as(Refusal, unknown.body).message
			);
		});
	});
});

/**
 * @proves A project with no bucket moves to another group alone, and a project that uses a bucket is
 * pointed at its bucket instead.
 */
describe('moving a project to another group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function loneProject(ownerGroupId: string) {
		return getProjectStore().create({
			name: 'lone',
			slug: `lone-${Math.random().toString(36).slice(2)}`,
			ownerGroupId,
			clientIds: ['client-a']
		});
	}

	it('gives the destination a project with no bucket, its clients unchanged', async () => {
		const w = await world();
		const project = await loneProject(w.personal._id);

		const { status } = await moveProject(w.aliceCookie, project._id, {
			groupId: w.team._id,
			confirm: true
		});

		expect(status).toBe(200);
		const stored = await getProjectStore().find(project._id);
		expect(stored?.ownerGroupId).toBe(w.team._id);
		expect(stored?.clientIds).toEqual(['client-a']);
	});

	it('previews a project move without confirmation, and moves nothing', async () => {
		const w = await world();
		const project = await loneProject(w.personal._id);

		const { status, body } = await moveProject(w.aliceCookie, project._id, {
			groupId: w.team._id
		});

		expect(status).toBe(409);
		expect(as(ProjectPreview, body).project.id).toBe(project._id);
		expect(await ownerOfProject(project._id)).toBe(w.personal._id);
	});

	it('refuses a project that uses a bucket, pointing to its bucket', async () => {
		const w = await world();

		const { status, body } = await moveProject(
			w.aliceCookie,
			w.projects[0]?._id ?? '',
			{ groupId: w.team._id, confirm: true }
		);

		expect(status).toBe(409);
		expect(as(Refusal, body).message).toBe(
			'a project using a bucket moves with its bucket'
		);
	});

	it('refuses the console’s own project', async () => {
		const superAdmin = await admin('super');
		const team = await regularGroup([superAdmin]);

		const { status } = await moveProject(
			await cookieFor(superAdmin),
			ADMIN_PROJECT_ID,
			{ groupId: team._id, confirm: true }
		);

		expect(status).toBe(403);
		expect(await ownerOfProject(ADMIN_PROJECT_ID)).not.toBe(team._id);
	});

	it('refuses a plain member of the project’s group', async () => {
		const w = await world();
		const project = await loneProject(w.team._id);
		const bobs = await ensurePersonalGroup(w.bob._id, w.bob.email);

		const { status } = await moveProject(w.bobCookie, project._id, {
			groupId: bobs._id,
			confirm: true
		});

		expect(status).toBe(403);
		expect(await ownerOfProject(project._id)).toBe(w.team._id);
	});
});
