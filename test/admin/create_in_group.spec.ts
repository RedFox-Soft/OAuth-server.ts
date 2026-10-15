import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	adapter,
	adminAuditStore,
	getBucketStore
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
	bucketWithClients,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes).use(clientRoutes);

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
	{ _id: Type.String(), ownerTeamId: Type.String() },
	{ additionalProperties: true }
);
const CreatedApplication = Type.Object(
	{ clientId: Type.String(), projectId: Type.String() },
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

/* An application in a bucket, as its Applications page would create it. */
const createApplication = (cookie: string, bucketId: string) =>
	call(`/admin/api/projects/${bucketId}/clients`, cookie, {
		clientName: unique('app'),
		grantTypes: ['client_credentials'],
		tokenEndpointAuthMethod: 'client_secret_basic'
	});

const createBucket = (cookie: string, body: Record<string, unknown> = {}) =>
	call('/admin/api/projects', cookie, {
		name: 'Created',
		slug: unique('b'),
		...body
	});

async function applicationsIn(bucketId: string) {
	return adapter('Client').findByIndexed('bucketId', bucketId);
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
	const { bucket: teamBucket } = await bucketWithClients(team._id, 0);
	const { bucket: personalBucket } = await bucketWithClients(personal._id, 0);
	const { bucket: othersBucket } = await bucketWithClients(others._id, 0);
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
 * @proves An administrator creates a bucket directly in any group they belong to, and an application in any
 * bucket of such a group, while a group they may not create in, another group's bucket, the Default bucket
 * and the administrators' bucket are refused with nothing created, and a bucket created without naming a
 * group lands in the active group as before.
 */
describe('creating in a chosen group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a bucket in another group the administrator belongs to', async () => {
		const w = await world();

		const res = await createBucket(w.cookie, { teamId: w.team._id });

		expect(res.status).toBe(201);
		const { _id } = shaped(Created, res.body);
		expect((await getBucketStore().find(_id))?.ownerGroupId).toBe(w.team._id);
	});

	it('creates an application in a bucket of another group the administrator belongs to', async () => {
		const w = await world();

		const res = await createApplication(w.cookie, w.teamBucket._id);

		expect(res.status).toBe(201);
		expect(shaped(CreatedApplication, res.body).projectId).toBe(
			w.teamBucket._id
		);
	});

	it("puts an application created in a bucket in that bucket's trail, under the bucket's group", async () => {
		const w = await world();

		const res = await createApplication(w.cookie, w.teamBucket._id);

		const { clientId } = shaped(CreatedApplication, res.body);
		const { entries } = await adminAuditStore.list({
			bucket: w.teamBucket._id,
			action: 'client.create'
		});
		expect(entries.map((e) => [e.targetId, e.ownerGroupId])).toEqual([
			[clientId, w.team._id]
		]);
	});

	it('creates a bucket in the active group when no group is named', async () => {
		const w = await world();

		const bucket = await createBucket(w.cookie);

		expect(shaped(Created, bucket.body).ownerTeamId).toBe(w.personal._id);
	});

	it('refuses a group the administrator is not a member of, and creates nothing', async () => {
		const w = await world();

		const bucket = await createBucket(w.cookie, { teamId: w.others._id });

		expect(bucket.status).toBe(403);
		expect(await getBucketStore().listByGroup(w.others._id)).toHaveLength(1);
	});

	it('refuses an application in a bucket of a group the administrator does not belong to, and creates nothing', async () => {
		const w = await world();

		const res = await createApplication(w.cookie, w.othersBucket._id);

		expect(res.status).toBe(403);
		expect(await applicationsIn(w.othersBucket._id)).toEqual([]);
	});

	it('answers a bucket that does not exist as one of another group, so nothing learns which exist', async () => {
		const w = await world();

		const unknown = await createApplication(w.cookie, 'no-such-bucket');
		const foreign = await createApplication(w.cookie, w.othersBucket._id);

		expect(unknown).toEqual(foreign);
	});

	it("refuses an application in the administrators' bucket, even to a super administrator", async () => {
		const superAdmin = await admin('super');
		const before = await applicationsIn(ADMIN_BUCKET_ID);

		const res = await createApplication(
			await cookieFor(superAdmin),
			ADMIN_BUCKET_ID
		);

		expect(res.status).toBe(403);
		expect(await applicationsIn(ADMIN_BUCKET_ID)).toEqual(before);
	});

	it('answers the Default bucket named by an administrator exactly as a bucket out of their reach', async () => {
		const w = await world();
		const before = await applicationsIn(DEFAULT_BUCKET_ID);

		const shared = await createApplication(w.cookie, DEFAULT_BUCKET_ID);
		const foreign = await createApplication(w.cookie, w.othersBucket._id);

		expect(shared).toEqual(foreign);
		expect(shared.status).toBe(403);
		expect(await applicationsIn(DEFAULT_BUCKET_ID)).toEqual(before);
	});

	it("refuses another administrator's personal group, even to a super administrator", async () => {
		const w = await world();
		const superAdmin = await admin('super');
		const bobsPersonal = await ensurePersonalGroup(w.bob._id, w.bob.email);

		const res = await createBucket(await cookieFor(superAdmin), {
			teamId: bobsPersonal._id
		});

		expect(res.status).toBe(403);
		expect(await getBucketStore().listByGroup(bobsPersonal._id)).toEqual([]);
	});

	it('refuses Super administrators as a group to create in', async () => {
		const superAdmin = await admin('super');

		const res = await createBucket(await cookieFor(superAdmin), {
			teamId: SUPER_ADMINS_GROUP_ID
		});

		expect(res.status).toBe(404);
		expect(await getBucketStore().listByGroup(SUPER_ADMINS_GROUP_ID)).toEqual(
			[]
		);
	});

	it('creates in a group a super administrator does not belong to', async () => {
		const w = await world();
		const superAdmin = await admin('super');

		const res = await createBucket(await cookieFor(superAdmin), {
			teamId: w.team._id
		});

		expect(res.status).toBe(201);
		expect(shaped(Created, res.body).ownerTeamId).toBe(w.team._id);
	});

	it('creates an application in a bucket of a group a super administrator does not belong to', async () => {
		const w = await world();
		const superAdmin = await admin('super');

		const res = await createApplication(
			await cookieFor(superAdmin),
			w.teamBucket._id
		);

		expect(res.status).toBe(201);
		expect(shaped(CreatedApplication, res.body).projectId).toBe(
			w.teamBucket._id
		);
	});
});
