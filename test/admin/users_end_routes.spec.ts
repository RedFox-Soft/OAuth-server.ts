import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getUserStore,
	getBucketStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from './answered.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes).use(endUserRoutes);
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

async function makeBucket(
	roles: string[] = [],
	ownerGroupId = UNASSIGNED_GROUP_ID
) {
	return getBucketStore().create({
		name: `b-${Math.random()}`,
		roles,
		ownerGroupId
	});
}

/**
 * @proves End-users are administered by those with rights over their bucket, never with a
 * password in a response, and never in the reserved admin bucket.
 */
describe('end-user API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access', async () => {
		const bucket = await makeBucket();
		const res = await client.admin.api.buckets({ id: bucket._id }).users.get();
		expect(res.status).toBe(401);
	});

	it('creates, lists (no password), edits, and deletes a user', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'u@x.io', password: 'supersecret', roles: ['viewer'] },
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
		const body = answered(created.data);
		expect(body).not.toHaveProperty('password');
		expect(body.verified).toBe(true);
		const uid = body._id;

		const list = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie } });
		const users = answered(list.data);
		expect(users.some((u) => u._id === uid)).toBe(true);
		expect(users.every((u) => !('password' in u))).toBe(true);

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.patch({ active: false }, { headers: { cookie } });
		expect(answered(patched.data).active).toBe(false);

		const del = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.delete(undefined, { headers: { cookie } });
		expect(del.status).toBe(200);
		expect(await getUserStore(bucket._id).find(uid)).toBeNull();
	});

	it('creates a user holding the claims it was given', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{
					email: 'claims-create@x.io',
					password: 'supersecret',
					claims: { name: 'Ada Lovelace', locale: 'en-GB' }
				},
				{ headers: { cookie } }
			);

		expect(created.status).toBe(201);
		expect(answered(created.data).claims).toEqual({
			name: 'Ada Lovelace',
			locale: 'en-GB'
		});
	});

	it('replaces a user’s claims with the ones an edit carries', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const user = await getUserStore(bucket._id).create('claims-edit@x.io', 'h');
		await getUserStore(bucket._id).update(user._id, {
			claims: { name: 'Before', nickname: 'old' }
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.patch(
				{ claims: { name: 'After', address: { country: 'GB' } } },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(200);
		expect(answered(res.data).claims).toEqual({
			name: 'After',
			address: { country: 'GB' }
		});
	});

	/*
	 * A claim is released as the account says it is, and `findAccount` spreads the stored claims last —
	 * so a stored `sub`, `email` or `email_verified` would stand in for the account's identity, and a
	 * protocol claim would stand in for what the server itself asserts about the sign-in.
	 */
	for (const reserved of [
		'sub',
		'email',
		'email_verified',
		'iss',
		'aud',
		'exp',
		'iat',
		'nbf',
		'jti',
		'nonce',
		'azp',
		'acr',
		'amr',
		'auth_time',
		'sid',
		'at_hash',
		'c_hash'
	]) {
		it(`refuses to set the ${reserved} claim on an account`, async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const bucket = await makeBucket();
			const user = await getUserStore(bucket._id).create(
				`reserved-${reserved}@x.io`,
				'h'
			);

			const res = await client.admin.api
				.buckets({ id: bucket._id })
				.users({ uid: user._id })
				.patch({ claims: { [reserved]: 'forged' } }, { headers: { cookie } });

			expect(res.status).toBe(422);
			expect(
				(await getUserStore(bucket._id).find(user._id))?.claims
			).toBeUndefined();
		});
	}

	it('keeps the claim values out of the audit trail', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const user = await getUserStore(bucket._id).create(
			'claims-audit@x.io',
			'h'
		);

		await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.patch(
				{ claims: { phone_number: '+44 20 7946 0000' } },
				{ headers: { cookie } }
			);

		const { entries } = await adminAuditStore.list({ targetId: user._id });
		expect(entries.length).toBeGreaterThan(0);
		expect(JSON.stringify(entries)).not.toContain('7946');
	});

	it('rejects roles not in the bucket set with 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket(['viewer']);
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'bad@x.io', password: 'supersecret', roles: ['admin'] },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(422);
	});

	it('rejects a duplicate email with 409', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const body = { email: 'dup@x.io', password: 'supersecret' };
		await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(body, { headers: { cookie } });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(body, { headers: { cookie } });
		expect(res.status).toBe(409);
	});

	it('resets a password (stores a new hash)', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bucket = await makeBucket();
		const created = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'pw@x.io', password: 'supersecret' },
				{ headers: { cookie } }
			);
		const uid = answered(created.data)._id;
		const before = (await getUserStore(bucket._id).find(uid))?.password;
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid })
			.password.post({ password: 'anothersecret' }, { headers: { cookie } });
		expect(res.status).toBe(200);
		const after = (await getUserStore(bucket._id).find(uid))?.password;
		expect(after).not.toBe(before);
	});

	it('lets a project_admin manage users of a bucket backing their project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket(); // not owned by pa
		const proj = await getProjectStore().create({
			name: 'PM',
			slug: `pm-${Math.random()}`,
			ownerGroupId: await personalGroupId(pa.userId)
		});
		await getProjectStore().update(proj._id, { bucketId: bucket._id });
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: 'via@x.io', password: 'supersecret' },
				{ headers: { cookie: pa.cookie } }
			);
		expect(res.status).toBe(201);
	});

	it('denies a project_admin a bucket they neither own nor reach via a project', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		const bucket = await makeBucket();
		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.get({ headers: { cookie: pa.cookie } });
		expect(res.status).toBe(403);
	});

	it('refuses to manage users of the reserved admin bucket', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.users.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});
});
