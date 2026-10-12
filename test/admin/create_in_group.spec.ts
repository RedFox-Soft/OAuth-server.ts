import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	SUPER_ADMINS_GROUP_ID
} from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes).use(projectRoutes);

async function call(
	path: string,
	cookie: string,
	body: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	const text = await response.text();
	const json = response.headers.get('content-type')?.includes('json');
	return {
		status: response.status,
		body: json && text ? (JSON.parse(text) as unknown) : text
	};
}

const Created = Type.Object(
	{
		_id: Type.String(),
		ownerGroupId: Type.String(),
		bucketId: Type.Optional(Type.Union([Type.String(), Type.Null()]))
	},
	{ additionalProperties: true }
);

function admin(kind: AdminKind = 'plain'): Promise<User> {
	return createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
}

function unique(prefix: string) {
	return `${prefix}-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')}`;
}

const createProject = (cookie: string, body: Record<string, unknown> = {}) =>
	call('/admin/api/projects', cookie, {
		name: 'Created',
		slug: unique('p'),
		...body
	});

const createBucket = (cookie: string, body: Record<string, unknown> = {}) =>
	call('/admin/api/buckets', cookie, {
		name: 'Created',
		slug: unique('b'),
		...body
	});

async function projectsNamed(slugPrefix: string) {
	return (await getProjectStore().list()).filter((p) =>
		p.slug.startsWith(slugPrefix)
	);
}

/*
 * Alice is in her personal group — where her console is pointed — and owns Team; Team holds a bucket. Bob
 * is another administrator with a group and a bucket of his own.
 */
async function world() {
	const alice = await admin();
	const bob = await admin();
	const personal = await ensurePersonalGroup(alice._id, alice.email);
	const team = await regularGroup([alice]);
	const others = await regularGroup([bob]);
	const { bucket: teamBucket } = await bucketWithProjects(team._id, 0);
	const { bucket: personalBucket } = await bucketWithProjects(personal._id, 0);
	const { bucket: othersBucket } = await bucketWithProjects(others._id, 0);
	return {
		alice,
		bob,
		cookie: await cookieFor(alice),
		personal,
		team,
		others,
		teamBucket,
		personalBucket,
		othersBucket
	};
}

/**
 * @proves An administrator creates a project or a bucket directly in any group they belong to — a project
 * already using a bucket of that group — while a group they may not create in, another group's bucket and
 * the administrators' bucket are refused with nothing created, and a creation that names no group lands in
 * the active group as before.
 */
describe('creating in a chosen group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a project in another group the administrator belongs to', async () => {
		const w = await world();

		const res = await createProject(w.cookie, { groupId: w.team._id });

		expect(res.status).toBe(201);
		expect(shaped(Created, res.body).ownerGroupId).toBe(w.team._id);
	});

	it('creates a bucket in another group the administrator belongs to', async () => {
		const w = await world();

		const res = await createBucket(w.cookie, { groupId: w.team._id });

		expect(res.status).toBe(201);
		const { _id } = shaped(Created, res.body);
		expect((await getBucketStore().find(_id))?.ownerGroupId).toBe(w.team._id);
	});

	it('creates a project already using a bucket of the chosen group', async () => {
		const w = await world();

		const res = await createProject(w.cookie, {
			groupId: w.team._id,
			bucketId: w.teamBucket._id
		});

		expect(res.status).toBe(201);
		const { _id } = shaped(Created, res.body);
		expect((await getProjectStore().find(_id))?.bucketId).toBe(
			w.teamBucket._id
		);
	});

	it("puts a project created with a bucket in that bucket's trail, naming the fields it set", async () => {
		const w = await world();

		const res = await createProject(w.cookie, {
			groupId: w.team._id,
			bucketId: w.teamBucket._id
		});

		const { _id } = shaped(Created, res.body);
		const { entries } = await adminAuditStore.list({
			bucket: w.teamBucket._id,
			action: 'project.create'
		});
		expect(
			entries.map((e) => [e.targetId, e.ownerGroupId, e.attributes])
		).toEqual([[_id, w.team._id, ['bucketId', 'groupId', 'name', 'slug']]]);
	});

	it('creates in the active group when no group is named', async () => {
		const w = await world();

		const project = await createProject(w.cookie);
		const bucket = await createBucket(w.cookie);

		expect([
			shaped(Created, project.body).ownerGroupId,
			shaped(Created, bucket.body).ownerGroupId
		]).toEqual([w.personal._id, w.personal._id]);
	});

	it('refuses a group the administrator is not a member of, and creates nothing', async () => {
		const w = await world();
		const slug = unique('refused');

		const project = await createProject(w.cookie, {
			slug,
			groupId: w.others._id
		});
		const bucket = await createBucket(w.cookie, { groupId: w.others._id });

		expect([project.status, bucket.status]).toEqual([403, 403]);
		expect(await projectsNamed(slug)).toEqual([]);
		expect(await getBucketStore().listByGroup(w.others._id)).toHaveLength(1);
	});

	it('refuses a bucket of another group than the one chosen, and creates nothing', async () => {
		const w = await world();
		const slug = unique('mixed');

		const res = await createProject(w.cookie, {
			slug,
			groupId: w.team._id,
			bucketId: w.personalBucket._id
		});

		expect(res.status).toBe(409);
		expect(await projectsNamed(slug)).toEqual([]);
	});

	it('refuses a bucket of a group the administrator does not belong to', async () => {
		const w = await world();
		const slug = unique('foreign');

		const res = await createProject(w.cookie, {
			slug,
			bucketId: w.othersBucket._id
		});

		expect(res.status).toBe(403);
		expect(await projectsNamed(slug)).toEqual([]);
	});

	it('answers a bucket that does not exist as one of another group, so nothing learns which exist', async () => {
		const w = await world();

		const unknown = await createProject(w.cookie, {
			bucketId: 'no-such-bucket'
		});
		const foreign = await createProject(w.cookie, {
			bucketId: w.othersBucket._id
		});

		expect(unknown).toEqual(foreign);
	});

	it("refuses the administrators' bucket, even to a super administrator", async () => {
		const superAdmin = await admin('super');

		const res = await createProject(await cookieFor(superAdmin), {
			bucketId: ADMIN_BUCKET_ID
		});

		expect(res.status).toBe(403);
	});

	it('refuses the default bucket by name, since leaving the bucket out uses it', async () => {
		const w = await world();

		const res = await createProject(w.cookie, { bucketId: DEFAULT_BUCKET_ID });

		expect(res.status).toBe(422);
	});

	it("refuses another administrator's personal group, even to a super administrator", async () => {
		const w = await world();
		const superAdmin = await admin('super');
		const bobsPersonal = await ensurePersonalGroup(w.bob._id, w.bob.email);

		const res = await createBucket(await cookieFor(superAdmin), {
			groupId: bobsPersonal._id
		});

		expect(res.status).toBe(403);
		expect(await getBucketStore().listByGroup(bobsPersonal._id)).toEqual([]);
	});

	it('refuses Super administrators as a group to create in', async () => {
		const superAdmin = await admin('super');

		const res = await createProject(await cookieFor(superAdmin), {
			groupId: SUPER_ADMINS_GROUP_ID
		});

		expect(res.status).toBe(404);
	});

	it('creates in a group a super administrator does not belong to', async () => {
		const w = await world();
		const superAdmin = await admin('super');

		const res = await createProject(await cookieFor(superAdmin), {
			groupId: w.team._id,
			bucketId: w.teamBucket._id
		});

		expect(res.status).toBe(201);
		expect(shaped(Created, res.body).ownerGroupId).toBe(w.team._id);
	});
});
