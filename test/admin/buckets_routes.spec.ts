import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function superCookie() {
	return (await sessionCookieFor(['super_admin'])).cookie;
}

describe('buckets API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a standalone bucket', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Dev users', roles: ['viewer'] },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = res.data as UserBucket | undefined;
		// Was `authMethods: ['password']`, a field nothing read. The coverage moves to the setting that
		// replaced it: a new bucket accepts passwords and holds no upstream providers.
		expect(created?.passwordLogin).toBe(true);
		expect(created?.federation).toEqual([]);
	});

	it('refuses to delete a bucket still referenced by a project', async () => {
		const cookie = await superCookie();
		const res1 = await client.admin.api.buckets.post(
			{ name: 'Shared' },
			{ headers: { cookie } }
		);
		const bucket = res1.data as UserBucket;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: 'p'
		});
		await getProjectStore().update(project._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('super_admin GET /admin/api/buckets returns all buckets', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const otherPa = await sessionCookieFor(['project_admin']);
		const a = await client.admin.api.buckets.post(
			{ name: 'Bucket A' },
			{ headers: { cookie } }
		);
		// Owned by another tenant, created as that administrator: ownership follows the active scope
		// of whoever creates it and is not a field a request can set.
		const b = await client.admin.api.buckets.post(
			{ name: 'Bucket B' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketA = a.data as UserBucket;
		const bucketB = b.data as UserBucket;
		const list = await client.admin.api.buckets.get({ headers: { cookie } });
		const buckets = list.data as UserBucket[];
		const ids = buckets.map((bucket) => bucket._id);
		expect(ids).toContain(bucketA._id);
		expect(ids).toContain(bucketB._id);
	});

	it('project_admin GET /admin/api/buckets returns only their own group’s', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const otherPa = await sessionCookieFor(['project_admin']);
		const mine = await client.admin.api.buckets.post(
			{ name: 'Mine' },
			{ headers: { cookie: pa.cookie } }
		);
		await client.admin.api.buckets.post(
			{ name: 'Other' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketMine = mine.data as UserBucket;
		const list = await client.admin.api.buckets.get({
			headers: { cookie: pa.cookie }
		});
		const buckets = list.data as UserBucket[];
		expect(buckets.map((bucket) => bucket._id)).toEqual([bucketMine._id]);
	});

	/*
	 * The reported defect, now asserted the other way round. This test was named "project_admin cannot
	 * create a bucket" and passed because the route answered 403 to an action the console still offered.
	 */
	it('project_admin creates a bucket into their own group', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const res = await client.admin.api.buckets.post(
			{ name: 'Allowed' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(res.status).toBe(201);
		expect((res.data as UserBucket).ownerGroupId).toBe(
			await personalGroupId(pa.userId)
		);
	});

	it('denies delete of an unreferenced bucket to a project_admin who does not manage it', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'Not managed by pa' },
			{ headers: { cookie: superSession.cookie } }
		);
		const bucket = created.data as UserBucket;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('super_admin deletes an unreferenced bucket successfully', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'To delete' },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
	});

	it('gets and patches a bucket (name + roles)', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Editable', roles: ['viewer'] },
			{ headers: { cookie } }
		);
		const bucket = created.data as UserBucket;
		const got = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie } });
		expect((got.data as UserBucket).name).toBe('Editable');
		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch(
				{ name: 'Renamed', roles: ['viewer', 'editor'] },
				{ headers: { cookie } }
			);
		expect((patched.data as UserBucket).name).toBe('Renamed');
		expect((patched.data as UserBucket).roles).toEqual(['viewer', 'editor']);
	});

	it('lets a project_admin read a bucket backing a project they manage', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		// bucket NOT owned by pa (managedBy empty)
		const created = await client.admin.api.buckets.post(
			{ name: 'Backing' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = created.data as UserBucket;
		// a project pa manages points at it
		const proj = await getProjectStore().create({
			ownerGroupId: await personalGroupId(pa.userId),
			name: 'PB',
			slug: `pb-${Math.random()}`
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const got = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: pa.cookie } });
		expect(got.status).toBe(200);
	});

	it('forbids a project_admin from editing a bucket they only reach via a project', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'BackingRO' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = created.data as UserBucket;
		const proj = await getProjectStore().create({
			name: 'PB2',
			slug: `pb2-${Math.random()}`,
			ownerGroupId: await personalGroupId(pa.userId)
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'nope' }, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('rejects managing the reserved admin bucket', async () => {
		const cookie = await superCookie();
		const got = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie } });
		expect(got.status).toBe(403);
		const list = await client.admin.api.buckets.get({ headers: { cookie } });
		expect(
			(list.data as UserBucket[]).some((b) => b._id === ADMIN_BUCKET_ID)
		).toBe(false);
	});

	/*
	 * Replaces the pair that asserted who could edit `managedBy`. Ownership is no longer a mutable field
	 * on the container at all — it is not in the update body — so the property worth pinning is that a
	 * PATCH cannot move a bucket between tenants, whoever sends it.
	 */
	it('never moves a bucket between groups through an update', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'MB' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = created.data as UserBucket;
		const before = bucket.ownerGroupId;

		const res = await client.admin.api.buckets({ id: bucket._id }).patch(
			// Submitted as an unknown field; the schema does not accept it.
			{ name: 'MB renamed', ownerGroupId: 'somewhere-else' } as never,
			{ headers: { cookie: su.cookie } }
		);

		expect([200, 422]).toContain(res.status);
		const after = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: su.cookie } });
		expect((after.data as UserBucket).ownerGroupId).toBe(before);
	});

	it('lets a group member rename a bucket their group owns', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const created = await client.admin.api.buckets.post(
			{ name: 'MBOwned' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = created.data as UserBucket;
		const ok = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'renamed' }, { headers: { cookie: pa.cookie } });
		expect(ok.status).toBe(200);
	});
});
