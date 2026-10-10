import { describe, it, expect, beforeEach, afterAll } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { answered } from './answered.ts';

/*
 * `normalize: false` because that is how lib/index.ts constructs the real app, and one assertion here
 * depends on it: with normalization on, an undeclared body field is stripped before validation, so a
 * schema that refuses it looks identical to one that accepts and ignores it.
 */
const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(bucketRoutes);
const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function sessionCookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${unique(kind)}@x.io`);
	const session = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, userId: user._id };
}

const SEEDED = {
	name: 'Administrators',
	totpRequired: false,
	registrationOpen: false,
	emailVerificationRequired: false
};

async function restoreSeededPolicy() {
	await getBucketStore().update(ADMIN_BUCKET_ID, SEEDED);
}

/**
 * @proves A super administrator configures the console's own bucket on the same settings operation as any
 * bucket, every change is recorded, and nobody scoped below them can see or touch it.
 */
describe("the administrators' bucket on the bucket settings", () => {
	let admin: { cookie: string; userId: string };

	beforeEach(async () => {
		await ensureAdminSeed();
		admin = await sessionCookieFor('super');
		await restoreSeededPolicy();
	});

	// The settings are module state shared with every later spec; a leaked one gates the console there.
	afterAll(restoreSeededPolicy);

	it("lists the administrators' bucket for a super administrator, marked as the console's own", async () => {
		const res = await client.admin.api.buckets.get({
			headers: { cookie: admin.cookie }
		});
		expect(res.status).toBe(200);
		const listed = answered(res.data).find((b) => b._id === ADMIN_BUCKET_ID);
		expect(listed?.reserved).toBe('administrators');
	});

	it('reads the second-factor requirement off by default', async () => {
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie: admin.cookie } });
		expect(res.status).toBe(200);
		expect(answered(res.data).totpRequired).toBe(false);
		expect(answered(res.data).reserved).toBe('administrators');
	});

	it('turns the second factor on and reads it back', async () => {
		const patched = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ totpRequired: true }, { headers: { cookie: admin.cookie } });
		expect(patched.status).toBe(200);
		expect(answered(patched.data).totpRequired).toBe(true);

		const read = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie: admin.cookie } });
		expect(answered(read.data).totpRequired).toBe(true);
	});

	it('turns the second factor back off', async () => {
		await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ totpRequired: true }, { headers: { cookie: admin.cookie } });
		const off = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ totpRequired: false }, { headers: { cookie: admin.cookie } });
		expect(off.status).toBe(200);
		expect(answered(off.data).totpRequired).toBe(false);
	});

	it('renames the bucket an authenticator app shows as the issuer', async () => {
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ name: 'Operators' }, { headers: { cookie: admin.cookie } });
		expect(res.status).toBe(200);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.name).toBe(
			'Operators'
		);
	});

	it('records the change against the actor, naming the fields and never their values', async () => {
		/*
		 * Identified as the entry *this call* added. The audit store outlives a spec file, `list` sorts
		 * newest first and breaks a same-millisecond tie on a random id, so "the first entry with this
		 * action" is a coin toss decided differently on Windows and on the Linux runner.
		 */
		const before = new Set(
			(
				await adminAuditStore.list({
					targetType: 'UserBucket',
					targetId: ADMIN_BUCKET_ID
				})
			).entries.map((e) => e._id)
		);

		await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ totpRequired: true }, { headers: { cookie: admin.cookie } });

		const { entries } = await adminAuditStore.list({
			targetType: 'UserBucket',
			targetId: ADMIN_BUCKET_ID
		});
		const entry = entries.find(
			(e) => e.action === 'bucket.update' && !before.has(e._id)
		);
		expect(entry?.actorId).toBe(admin.userId);
		expect(entry?.attributes).toContain('totpRequired');
		expect(entry?.ownerGroupId).toBe(UNASSIGNED_GROUP_ID);
	});

	it('opens administrator registration and warns that, without verification, any address can be claimed', async () => {
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ registrationOpen: true }, { headers: { cookie: admin.cookie } });
		expect(res.status).toBe(200);
		expect(answered(res.data).registrationOpen).toBe(true);
		expect(answered(res.data).advisory).toContain('any address can be claimed');
	});

	it('refuses a setting the bucket does not have', async () => {
		const res = await client.admin.api.buckets({ id: ADMIN_BUCKET_ID }).patch(
			{
				totpRequired: true,
				// @ts-expect-error a field no bucket carries; the schema refuses it
				superAdmin: true
			},
			{ headers: { cookie: admin.cookie } }
		);
		expect(res.status).toBe(422);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
			false
		);
	});

	describe('requiring administrators to verify their address', () => {
		const MAIL: SmtpSettings = {
			host: 'smtp.example.test',
			port: 587,
			secure: false,
			username: '',
			password: '',
			fromName: 'Console',
			fromEmail: 'console@example.test'
		};
		// The stores have no delete; an empty host is what "not configured" means to the mailer.
		const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };
		let previousMail: SmtpSettings | null = null;

		beforeEach(async () => {
			previousMail = await getSmtpSettingsStore().get();
		});

		afterAll(async () => {
			await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
		});

		async function verifyActing() {
			await getUserStore(ADMIN_BUCKET_ID).update(admin.userId, {
				verified: true
			});
		}

		it('is refused while mail delivery is not configured', async () => {
			await getSmtpSettingsStore().set(NO_MAIL);
			await verifyActing();

			const res = await client.admin.api
				.buckets({ id: ADMIN_BUCKET_ID })
				.patch(
					{ emailVerificationRequired: true },
					{ headers: { cookie: admin.cookie } }
				);

			expect(res.status).toBe(409);
			expect(
				(await getBucketStore().find(ADMIN_BUCKET_ID))
					?.emailVerificationRequired
			).toBe(false);
		});

		it('is refused while the acting super administrator has not verified their own address', async () => {
			await getSmtpSettingsStore().set(MAIL);

			const res = await client.admin.api
				.buckets({ id: ADMIN_BUCKET_ID })
				.patch(
					{ emailVerificationRequired: true },
					{ headers: { cookie: admin.cookie } }
				);

			expect(res.status).toBe(409);
			expect(
				(await getBucketStore().find(ADMIN_BUCKET_ID))
					?.emailVerificationRequired
			).toBe(false);
		});

		it('is accepted from a verified super administrator with mail delivery configured', async () => {
			await getSmtpSettingsStore().set(MAIL);
			await verifyActing();

			const res = await client.admin.api
				.buckets({ id: ADMIN_BUCKET_ID })
				.patch(
					{ emailVerificationRequired: true, verificationMethod: 'code' },
					{ headers: { cookie: admin.cookie } }
				);

			expect(res.status).toBe(200);
			expect(answered(res.data).emailVerificationRequired).toBe(true);
		});
	});

	describe('for an administrator who is not a super administrator', () => {
		let weaker: { cookie: string; userId: string };

		beforeEach(async () => {
			weaker = await sessionCookieFor('plain');
		});

		it("does not list the administrators' bucket", async () => {
			const res = await client.admin.api.buckets.get({
				headers: { cookie: weaker.cookie }
			});
			expect(answered(res.data).some((b) => b._id === ADMIN_BUCKET_ID)).toBe(
				false
			);
		});

		it("refuses to read the administrators' bucket", async () => {
			const res = await client.admin.api
				.buckets({ id: ADMIN_BUCKET_ID })
				.get({ headers: { cookie: weaker.cookie } });
			expect(res.status).toBe(403);
		});

		it("refuses to change the administrators' bucket", async () => {
			const res = await client.admin.api
				.buckets({ id: ADMIN_BUCKET_ID })
				.patch({ totpRequired: true }, { headers: { cookie: weaker.cookie } });
			expect(res.status).toBe(403);
			expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
				false
			);
		});
	});

	it('refuses an unauthenticated caller', async () => {
		expect(
			(await client.admin.api.buckets({ id: ADMIN_BUCKET_ID }).get()).status
		).toBe(401);
		const patched = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ totpRequired: true });
		expect(patched.status).toBe(401);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
			false
		);
	});
});
