import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { encodeBase32 } from 'lib/totp/base32.ts';
import { attemptKey } from 'lib/totp/verify.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import type { User } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(endUserRoutes);
const client = treaty(app);

const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique(roles.join('-'))}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, userId: user._id };
}

async function enrolledAccount(bucketId: string) {
	const user = await getUserStore(bucketId).create(
		`${unique('member')}@x.io`,
		'hash',
		[]
	);
	await getUserStore(bucketId).update(user._id, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 42 }
	});
	return user;
}

describe('clearing a lost authenticator (US5)', () => {
	let bucketId: string;
	let admin: { cookie: string; userId: string };

	beforeEach(async () => {
		await ensureAdminSeed();
		admin = await sessionCookieFor(['super_admin']);
		const bucket = await getBucketStore().create({
			name: unique('Recovery'),
			ownerGroupId: await personalGroupId(admin.userId),
			totpRequired: true
		});
		bucketId = bucket._id;
	});

	it('reports whether an account is enrolled, and when', async () => {
		const user = await enrolledAccount(bucketId);
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users.get({ headers: { cookie: admin.cookie } });

		expect(res.status).toBe(200);
		const listed = (res.data as { _id: string }[]).find(
			(u) => u._id === user._id
		) as { totpEnrolled?: boolean; totpEnrolledAt?: string } | undefined;
		expect(listed?.totpEnrolled).toBe(true);
		expect(listed?.totpEnrolledAt).toBeTruthy();
	});

	it('reports an unenrolled account as such', async () => {
		const user = await getUserStore(bucketId).create(
			`${unique('plain')}@x.io`,
			'hash',
			[]
		);
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users.get({ headers: { cookie: admin.cookie } });
		const listed = (res.data as { _id: string }[]).find(
			(u) => u._id === user._id
		) as { totpEnrolled?: boolean; totpEnrolledAt?: string | null } | undefined;
		expect(listed?.totpEnrolled).toBe(false);
		expect(listed?.totpEnrolledAt).toBeNull();
	});

	/*
	 * The property the whole design rests on. TOTP verification is symmetric, so the server must hold a
	 * recoverable secret — which makes "it never leaves through a read" the only protection there is.
	 */
	it('never emits the secret through any end-user read', async () => {
		await enrolledAccount(bucketId);

		const list = await client.admin.api
			.buckets({ id: bucketId })
			.users.get({ headers: { cookie: admin.cookie } });
		expect(JSON.stringify(list.data)).not.toContain(SECRET);
		expect(JSON.stringify(list.data)).not.toContain('"totp"');

		const created = await client.admin.api
			.buckets({ id: bucketId })
			.users.post(
				{ email: `${unique('fresh')}@x.io`, password: 'hunter22hunter' },
				{ headers: { cookie: admin.cookie } }
			);
		expect(JSON.stringify(created.data)).not.toContain('"totp"');
		expect(JSON.stringify(created.data)).not.toContain('"password"');
	});

	it('clears the enrolment, immediately', async () => {
		const user = await enrolledAccount(bucketId);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });

		expect(res.status).toBe(200);
		const after = await getUserStore(bucketId).find(user._id);
		expect(after?.totp).toBeUndefined();
	});

	it('ends the account sessions, so none outlives the factor that made it', async () => {
		const user = await enrolledAccount(bucketId);
		await adapter('Session').upsert(
			'session-to-die',
			{ accountId: user._id, uid: 'u1', exp: epochTime() + 600 },
			600
		);

		await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });

		expect(await adapter('Session').find('session-to-die')).toBeUndefined();
	});

	it('clears any standing lockout, so a fresh enrolment is not born throttled', async () => {
		const user = await enrolledAccount(bucketId);
		const key = attemptKey(bucketId, user._id);
		await adapter('TotpAttempt').upsert(
			key,
			{
				accountId: user._id,
				failures: 99,
				windowStart: epochTime(),
				exp: epochTime() + 600
			},
			600
		);

		await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });

		expect(await adapter('TotpAttempt').find(key)).toBeUndefined();
	});

	it('succeeds on an account that holds no authenticator', async () => {
		const user = await getUserStore(bucketId).create(
			`${unique('none')}@x.io`,
			'hash',
			[]
		);
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });
		// An operator should not have to know the current state to reach the intended one.
		expect(res.status).toBe(200);
	});

	it('answers 404 for an account that does not exist', async () => {
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: 'no-such-account' })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });
		expect(res.status).toBe(404);
	});

	it('refuses a caller with no rights over the bucket, changing nothing', async () => {
		const user = await enrolledAccount(bucketId);
		const outsider = await sessionCookieFor(['project_admin']);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: outsider.cookie } });

		expect(res.status).toBe(403);
		const after = await getUserStore(bucketId).find(user._id);
		expect(after?.totp?.secret).toBe(SECRET);
	});

	it('refuses an unauthenticated caller, changing nothing', async () => {
		const user = await enrolledAccount(bucketId);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete();

		expect(res.status).toBe(401);
		const after = await getUserStore(bucketId).find(user._id);
		expect(after?.totp?.secret).toBe(SECRET);
	});

	it('records the act against the actor, naming no value', async () => {
		const user = await enrolledAccount(bucketId);

		await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });

		const { entries } = await adminAuditStore.list({
			targetType: 'EndUser',
			targetId: user._id
		});
		const entry = entries.find((e) => e.action === 'enduser.totp.clear');
		expect(entry).toBeDefined();
		expect(entry?.actorId).toBe(admin.userId);
		expect(entry?.targetScope).toBe(bucketId);
		expect(entry?.timestamp).toBeDefined();
		expect(JSON.stringify(entry)).not.toContain(SECRET);
	});

	// Clearing is a reset, not a deletion: consent survives it. Conflating the two is how a password
	// change would start destroying grants.
	it('leaves the account itself and its grants alone', async () => {
		const user = await enrolledAccount(bucketId);
		await adapter('Grant').upsert(
			'grant-that-stays',
			{
				accountId: user._id,
				clientId: 'c',
				trusted: false,
				createdAt: epochTime(),
				lastModifiedAt: epochTime(),
				exp: epochTime() + 600
			},
			600
		);

		await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: user._id })
			.totp.delete(undefined, { headers: { cookie: admin.cookie } });

		expect(await adapter('Grant').find('grant-that-stays')).toBeDefined();
		const after = (await getUserStore(bucketId).find(user._id)) as User;
		expect(after.email).toBeTruthy();
		expect(after.active).toBe(true);
	});
});
