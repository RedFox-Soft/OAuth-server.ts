import {
	describe,
	it,
	expect,
	afterAll,
	beforeAll,
	beforeEach
} from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';
import { createAdministrator } from '../administrators.ts';
import { consenting } from './sign_in_consent.ts';

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};
// The stores have no delete; an empty host is what "not configured" means to the mailer.
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function superCookie() {
	const user = await createAdministrator('super', `su-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

/**
 * @proves An operator sets a bucket registration and verification policy, gets safe defaults if
 * they set nothing, and the change is recorded.
 */
describe('bucket verification settings API', () => {
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		previousMail = await getSmtpSettingsStore().get();
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await getSmtpSettingsStore().set(MAIL);
	});

	// Mail settings are process-wide; a later spec must find them as this one did.
	afterAll(async () => {
		await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
	});

	it('defaults new buckets to closed sign-up and verification off', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Defaults', slug: 'defaults-1' },
			{ headers: { cookie } }
		);
		const bucket = answered(res.data);
		expect(bucket.registrationOpen).toBe(false);
		expect(bucket.emailVerificationRequired).toBe(false);
		expect(bucket.verificationMethod).toBe('link');
	});

	it('creates a bucket open to sign-up when that is asked for', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: 'Open', slug: 'open-sign-up-1', registrationOpen: true },
			{ headers: { cookie } }
		);
		expect(answered(res.data).registrationOpen).toBe(true);
	});

	it('leaves the sign-up of a bucket stored before the default changed as it was', async () => {
		const cookie = await superCookie();
		const stored = await getBucketStore().create({
			name: 'Older',
			slug: 'older-sign-up-1',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		const res = await client.admin.api
			.buckets({ id: stored._id })
			.get({ headers: { cookie } });

		expect(answered(res.data).registrationOpen).toBe(true);
	});

	it('persists a settings patch and records an audit entry', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Settable', slug: 'settable-2', registrationOpen: true },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const patched = await consenting((consent) =>
			client.admin.api.buckets({ id: bucket._id }).patch(
				{
					registrationOpen: false,
					emailVerificationRequired: true,
					verificationMethod: 'code',
					...consent
				},
				{ headers: { cookie } }
			)
		);
		expect(patched.status).toBe(200);
		const after = answered(patched.data);
		expect(after.registrationOpen).toBe(false);
		expect(after.emailVerificationRequired).toBe(true);
		expect(after.verificationMethod).toBe('code');

		const { entries } = await adminAuditStore.list({
			targetType: 'UserBucket',
			targetId: bucket._id
		});
		expect(entries.some((a) => a.action === 'bucket.update')).toBe(true);
	});

	// This entry used to be written only when a registration or verification field was present, so a
	// rename left no trace — while still being an exercised privilege over a bucket.
	it('audits an update that touches no verification field', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'Rename me', slug: 'rename-me-3' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'Renamed' }, { headers: { cookie } });
		expect(patched.status).toBe(200);

		const { entries } = await adminAuditStore.list({
			targetId: bucket._id,
			action: 'bucket.update'
		});
		expect(entries).toHaveLength(1);
	});

	describe('requiring verification while mail delivery is not configured', () => {
		beforeEach(async () => {
			await getSmtpSettingsStore().set(NO_MAIL);
		});

		it('is refused on an ordinary bucket, and nothing is recorded', async () => {
			const cookie = await superCookie();
			const bucket = answered(
				(
					await client.admin.api.buckets.post(
						{ name: 'Mailless', slug: 'mailless-1' },
						{ headers: { cookie } }
					)
				).data
			);

			const res = await client.admin.api
				.buckets({ id: bucket._id })
				.patch(
					{ emailVerificationRequired: true, confirm: true, expect: {} },
					{ headers: { cookie } }
				);

			expect(res.status).toBe(409);
			expect(JSON.stringify(res.error?.value)).toContain(
				'configure mail delivery first'
			);
			expect(
				(await getBucketStore().find(bucket._id))?.emailVerificationRequired
			).toBe(false);
			const { entries } = await adminAuditStore.list({
				targetId: bucket._id,
				action: 'bucket.update'
			});
			expect(entries).toHaveLength(0);
		});

		it('still lets a bucket turn the requirement off', async () => {
			const cookie = await superCookie();
			const stored = await getBucketStore().create({
				name: 'Was verifying',
				slug: 'was-verifying-1',
				ownerGroupId: UNASSIGNED_GROUP_ID,
				emailVerificationRequired: true
			});

			const res = await client.admin.api
				.buckets({ id: stored._id })
				.patch({ emailVerificationRequired: false }, { headers: { cookie } });

			expect(res.status).toBe(200);
			expect(answered(res.data).emailVerificationRequired).toBe(false);
		});
	});

	it('rejects an invalid verification method', async () => {
		const cookie = await superCookie();
		const created = await client.admin.api.buckets.post(
			{ name: 'BadMethod', slug: 'badmethod-4' },
			{ headers: { cookie } }
		);
		const bucket = answered(created.data);
		const res = await client.admin.api.buckets({ id: bucket._id }).patch(
			// @ts-expect-error a verification method the schema does not offer
			{ verificationMethod: 'sms' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});
});
