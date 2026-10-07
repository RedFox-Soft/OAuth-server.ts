import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from './answered.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function sessionCookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function superCookie() {
	return (await sessionCookieFor('super')).cookie;
}

/**
 * @proves Buckets are administered only by those with rights over them, are never moved between
 * groups by an update, and cannot be deleted while a project still points at them.
 */
describe('buckets API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a standalone bucket', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Dev users', slug: 'dev-users-1' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = answered(res.data);
		// Was `authMethods: ['password']`, a field nothing read. The coverage moves to the setting that
		// replaced it: a new bucket accepts passwords and holds no upstream providers.
		expect(created.passwordLogin).toBe(true);
		expect(created.federation).toEqual([]);
	});

	it('refuses to delete a bucket still referenced by a project', async () => {
		const cookie = await superCookie();
		const res1 = await client.admin.api.buckets.post(
			{ name: 'Shared', slug: 'shared-2' },
			{ headers: { cookie } }
		);
		const bucket = answered(res1.data);
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

	it('a super administrator GET /admin/api/buckets returns all buckets', async () => {
		const { cookie } = await sessionCookieFor('super');
		const otherPa = await sessionCookieFor('plain');
		const a = await client.admin.api.buckets.post(
			{ name: 'Bucket A', slug: 'bucket-a-3' },
			{ headers: { cookie } }
		);
		// Owned by another tenant, created as that administrator: ownership follows the active scope
		// of whoever creates it and is not a field a request can set.
		const b = await client.admin.api.buckets.post(
			{ name: 'Bucket B', slug: 'bucket-b-4' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketA = answered(a.data);
		const bucketB = answered(b.data);
		const list = await client.admin.api.buckets.get({ headers: { cookie } });
		const buckets = answered(list.data);
		const ids = buckets.map((bucket) => bucket._id);
		expect(ids).toContain(bucketA._id);
		expect(ids).toContain(bucketB._id);
	});

	it('a project administrator GET /admin/api/buckets returns only their own group’s', async () => {
		const pa = await sessionCookieFor('plain');
		const otherPa = await sessionCookieFor('plain');
		const mine = await client.admin.api.buckets.post(
			{ name: 'Mine', slug: 'mine-5' },
			{ headers: { cookie: pa.cookie } }
		);
		await client.admin.api.buckets.post(
			{ name: 'Other', slug: 'other-6' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketMine = answered(mine.data);
		const list = await client.admin.api.buckets.get({
			headers: { cookie: pa.cookie }
		});
		const buckets = answered(list.data);
		expect(buckets.map((bucket) => bucket._id)).toEqual([bucketMine._id]);
	});

	/*
	 * The reported defect, now asserted the other way round. This test was named "project administrator cannot
	 * create a bucket" and passed because the route answered 403 to an action the console still offered.
	 */
	it('a project administrator creates a bucket into their own group', async () => {
		const pa = await sessionCookieFor('plain');
		const res = await client.admin.api.buckets.post(
			{ name: 'Allowed', slug: 'allowed-7' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(res.status).toBe(201);
		expect(answered(res.data).ownerGroupId).toBe(
			await personalGroupId(pa.userId)
		);
	});

	it('denies delete of an unreferenced bucket to a project administrator who does not manage it', async () => {
		const superSession = await sessionCookieFor('super');
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.buckets.post(
			{ name: 'Not managed by pa', slug: 'not-managed-by-pa-8' },
			{ headers: { cookie: superSession.cookie } }
		);
		const bucket = answered(created.data);
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('a super administrator deletes an unreferenced bucket successfully', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'To delete', slug: 'to-delete-9' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
	});

	it('gets and renames a bucket', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Editable', slug: 'editable-10' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const got = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie } });
		expect(answered(got.data).name).toBe('Editable');
		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'Renamed' }, { headers: { cookie } });
		expect(answered(patched.data).name).toBe('Renamed');
	});

	it('lets a project administrator read a bucket backing a project they manage', async () => {
		const su = await sessionCookieFor('super');
		const pa = await sessionCookieFor('plain');
		// bucket NOT owned by pa (managedBy empty)
		const created = await client.admin.api.buckets.post(
			{ name: 'Backing', slug: 'backing-11' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = answered(created.data);
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

	it('forbids a project administrator from editing a bucket they only reach via a project', async () => {
		const su = await sessionCookieFor('super');
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.buckets.post(
			{ name: 'BackingRO', slug: 'backingro-12' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = answered(created.data);
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
		expect(answered(list.data).some((b) => b._id === ADMIN_BUCKET_ID)).toBe(
			false
		);
	});

	/*
	 * Replaces the pair that asserted who could edit `managedBy`. Ownership is no longer a mutable field
	 * on the container at all — it is not in the update body — so the property worth pinning is that a
	 * PATCH cannot move a bucket between tenants, whoever sends it.
	 */
	it('never moves a bucket between groups through an update', async () => {
		const su = await sessionCookieFor('super');
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.buckets.post(
			{ name: 'MB', slug: 'mb-13' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = answered(created.data);
		const before = bucket.ownerGroupId;

		const res = await client.admin.api.buckets({ id: bucket._id }).patch(
			// @ts-expect-error submitted as an unknown field; the schema does not accept it.
			{ name: 'MB renamed', ownerGroupId: 'somewhere-else' },
			{ headers: { cookie: su.cookie } }
		);

		expect([200, 422]).toContain(res.status);
		const after = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: su.cookie } });
		expect(answered(after.data).ownerGroupId).toBe(before);
	});

	it('lets a group member rename a bucket their group owns', async () => {
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.buckets.post(
			{ name: 'MBOwned', slug: 'mbowned-14' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = answered(created.data);
		const ok = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'renamed' }, { headers: { cookie: pa.cookie } });
		expect(ok.status).toBe(200);
	});
});
