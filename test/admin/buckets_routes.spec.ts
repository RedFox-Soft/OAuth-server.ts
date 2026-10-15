import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
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
 * @proves Buckets are administered only by members of the group that owns them or a super
 * administrator, and are never moved between groups by an update.
 */
describe('buckets API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a standalone bucket', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.projects.post(
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

	it('lists every bucket to a super administrator', async () => {
		const { cookie } = await sessionCookieFor('super');
		const otherPa = await sessionCookieFor('plain');
		const a = await client.admin.api.projects.post(
			{ name: 'Bucket A', slug: 'bucket-a-3' },
			{ headers: { cookie } }
		);
		// Owned by another tenant, created as that administrator: ownership follows the active scope
		// of whoever creates it and is not a field a request can set.
		const b = await client.admin.api.projects.post(
			{ name: 'Bucket B', slug: 'bucket-b-4' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketA = answered(a.data);
		const bucketB = answered(b.data);
		const list = await client.admin.api.projects.get({ headers: { cookie } });
		const buckets = answered(list.data);
		const ids = buckets.map((bucket) => bucket._id);
		expect(ids).toContain(bucketA._id);
		expect(ids).toContain(bucketB._id);
	});

	it('lists to an administrator who is not a super administrator only their own group’s buckets', async () => {
		const pa = await sessionCookieFor('plain');
		const otherPa = await sessionCookieFor('plain');
		const mine = await client.admin.api.projects.post(
			{ name: 'Mine', slug: 'mine-5' },
			{ headers: { cookie: pa.cookie } }
		);
		await client.admin.api.projects.post(
			{ name: 'Other', slug: 'other-6' },
			{ headers: { cookie: otherPa.cookie } }
		);
		const bucketMine = answered(mine.data);
		const list = await client.admin.api.projects.get({
			headers: { cookie: pa.cookie }
		});
		const buckets = answered(list.data);
		expect(buckets.map((bucket) => bucket._id)).toEqual([bucketMine._id]);
	});

	/*
	 * The reported defect, now asserted the other way round. This test was named "project administrator cannot
	 * create a bucket" and passed because the route answered 403 to an action the console still offered.
	 */
	it('creates a bucket into the group of an administrator who is not a super administrator', async () => {
		const pa = await sessionCookieFor('plain');
		const res = await client.admin.api.projects.post(
			{ name: 'Allowed', slug: 'allowed-7' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(res.status).toBe(201);
		expect(answered(res.data).ownerTeamId).toBe(
			await personalGroupId(pa.userId)
		);
	});

	it('refuses deleting an empty bucket to an administrator outside its group', async () => {
		const superSession = await sessionCookieFor('super');
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.projects.post(
			{ name: 'Not managed by pa', slug: 'not-managed-by-pa-8' },
			{ headers: { cookie: superSession.cookie } }
		);
		const bucket = answered(created.data);
		const res = await client.admin.api
			.projects({ id: bucket._id })
			.delete(undefined, { headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('deletes an empty bucket for a super administrator', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.projects.post(
			{ name: 'To delete', slug: 'to-delete-9' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const res = await client.admin.api
			.projects({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
	});

	it('gets and renames a bucket', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.projects.post(
			{ name: 'Editable', slug: 'editable-10' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const got = await client.admin.api
			.projects({ id: bucket._id })
			.get({ headers: { cookie } });
		expect(answered(got.data).name).toBe('Editable');
		const patched = await client.admin.api
			.projects({ id: bucket._id })
			.patch({ name: 'Renamed' }, { headers: { cookie } });
		expect(answered(patched.data).name).toBe('Renamed');
	});

	it('refuses reading and renaming a bucket to an administrator outside the group that owns it', async () => {
		const su = await sessionCookieFor('super');
		const outsider = await sessionCookieFor('plain');
		const created = await client.admin.api.projects.post(
			{ name: 'NotTheirs', slug: 'not-theirs-12' },
			{ headers: { cookie: su.cookie } }
		);
		const bucket = answered(created.data);

		const got = await client.admin.api
			.projects({ id: bucket._id })
			.get({ headers: { cookie: outsider.cookie } });
		const renamed = await client.admin.api
			.projects({ id: bucket._id })
			.patch({ name: 'nope' }, { headers: { cookie: outsider.cookie } });

		expect(got.status).toBe(403);
		expect(renamed.status).toBe(403);
	});

	it("keeps the administrators' bucket out of reach of an administrator who is not a super administrator", async () => {
		const { cookie } = await sessionCookieFor('plain');
		const got = await client.admin.api
			.projects({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie } });
		expect(got.status).toBe(403);
		const list = await client.admin.api.projects.get({ headers: { cookie } });
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
		const created = await client.admin.api.projects.post(
			{ name: 'MB', slug: 'mb-13' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = answered(created.data);
		const before = bucket.ownerTeamId;

		const res = await client.admin.api.projects({ id: bucket._id }).patch(
			{
				name: 'MB renamed',
				// @ts-expect-error submitted as unknown fields, the edge name and the stored one; the schema accepts neither.
				ownerTeamId: 'somewhere-else',
				ownerGroupId: 'somewhere-else'
			},
			{ headers: { cookie: su.cookie } }
		);

		expect([200, 422]).toContain(res.status);
		const after = await client.admin.api
			.projects({ id: bucket._id })
			.get({ headers: { cookie: su.cookie } });
		expect(answered(after.data).ownerTeamId).toBe(before);
	});

	it('lets a group member rename a bucket their group owns', async () => {
		const pa = await sessionCookieFor('plain');
		const created = await client.admin.api.projects.post(
			{ name: 'MBOwned', slug: 'mbowned-14' },
			{ headers: { cookie: pa.cookie } }
		);
		const bucket = answered(created.data);
		const ok = await client.admin.api
			.projects({ id: bucket._id })
			.patch({ name: 'renamed' }, { headers: { cookie: pa.cookie } });
		expect(ok.status).toBe(200);
	});
});
