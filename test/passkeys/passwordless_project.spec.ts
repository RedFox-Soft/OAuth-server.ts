import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { configuration } from 'lib/configs/application.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { createAdministrator } from '../administrators.ts';
import { shaped } from '../shape.ts';
import { mailOn, person, seedPasskey } from './helpers.ts';

async function adminReq(
	method: string,
	path: string,
	cookie: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				...(body === undefined ? {} : { 'content-type': 'application/json' }),
				cookie
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text
			? shaped(Type.Record(Type.String(), Type.Unknown()), JSON.parse(text))
			: {}
	};
}

async function superCookie(
	userId: string,
	acr: string = configuration.acrMap.password
): Promise<string> {
	const session = await createAdminSession({
		userId,
		bucketId: ADMIN_BUCKET_ID,
		signedInWith: null,
		signInAcr: acr,
		signInAmr:
			acr === configuration.acrMap.phishing_resistant
				? ['hwk', 'user']
				: ['pwd'],
		signInAt: epochTime(),
		tokens: { accessToken: 'tok' }
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function freshProject(): Promise<string> {
	const bucket = await getBucketStore().create({
		name: `pwless-${Math.random().toString(36).slice(2, 8)}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	return bucket._id;
}

/**
 * @proves Passwordless projects (Spec 145 US1 & Q3=A): turning password sign-in off with passkeys and no IdP
 * requires mail delivery and either open registration or a passkey holder, previews named affected accounts with
 * `expect.withoutWayIn`, validates the three new passkey flags across regular and administrators' projects, and
 * allows passwordless console sign-in for passkey-authenticated super administrators.
 */
describe('passwordless project settings and guards', () => {
	let adminId: string;
	let pwdCookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		const admin = await createAdministrator(
			'super',
			`pwless-admin-${Math.random()}@x.io`
		);
		adminId = admin._id;
		await getUserStore(ADMIN_BUCKET_ID).update(adminId, { verified: true });
		pwdCookie = await superCookie(adminId);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passwordLogin: true,
			passkeyLogin: false,
			consolePasskeyRequired: false
		});
	});

	it('refuses turning passwords off on a passkey-only project when mail is off or no one can enter', async () => {
		const id = await freshProject();
		await getBucketStore().update(id, {
			passkeyLogin: true,
			registrationOpen: false
		});

		// Registration closed + 0 passkey holders -> 409
		const noHolders = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passwordLogin: false
			}
		);
		expect(noHolders.status).toBe(409);
		expect(String(noHolders.body.message)).toContain('passkey');

		// Mail off -> 409 even if registration is open
		await mailOn(false);
		const noMail = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passwordLogin: false,
				registrationOpen: true
			}
		);
		expect(noMail.status).toBe(409);
		expect(String(noMail.body.message)).toContain('mail');
	});

	it('previews affected users with expect.withoutWayIn and applies passwordless mode on confirmation', async () => {
		const id = await freshProject();
		await getBucketStore().update(id, {
			passkeyLogin: true,
			registrationOpen: true
		});
		const withPk = await person(id);
		await seedPasskey(id, withPk.accountId);
		const withoutPk = await person(id);

		const preview = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passwordLogin: false
			}
		);
		expect(preview.status).toBe(409);
		expect(preview.body.confirmationRequired).toBe(true);
		expect(preview.body.expect).toEqual({ withoutWayIn: 1 });
		const consequences = preview.body.consequences as string[];
		expect(consequences.some((c) => c.includes(withoutPk.email))).toBe(true);
		expect(
			consequences.some((c) =>
				c.includes('Self-service passkey recovery is off')
			)
		).toBe(true);

		// Wrong expect count refused
		const stale = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passwordLogin: false,
				confirm: true,
				expect: { withoutWayIn: 0 }
			}
		);
		expect(stale.status).toBe(409);

		// Exact expect count succeeds
		const applied = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passwordLogin: false,
				confirm: true,
				expect: { withoutWayIn: 1 }
			}
		);
		expect(applied.status).toBe(200);
		expect(applied.body.passwordLogin).toBe(false);

		// Summary reports adoption metrics
		const summary = await adminReq(
			'GET',
			`/admin/api/projects/${id}/summary`,
			pwdCookie
		);
		expect(summary.status).toBe(200);
		expect(summary.body.passkeyHolders).toBe(1);
		expect(summary.body.withoutPasskey).toBe(1);
		expect(summary.body.passkeyCampaignSkipped).toBe(0);
		expect(summary.body.providerOnlyPasskeyHolders).toBe(0);
	});

	it('enforces flag dependencies and rejects non-admin flags on the administrators project', async () => {
		const id = await freshProject();

		// Turning on flags while passkeys are off -> 409 passkeys_not_accepted
		for (const field of [
			'passkeyRecovery',
			'passkeyRequired',
			'passkeyForFederated'
		] as const) {
			const res = await adminReq(
				'PATCH',
				`/admin/api/projects/${id}`,
				pwdCookie,
				{
					[field]: true
				}
			);
			expect(res.status).toBe(409);
			expect(res.body.code).toBe('passkeys_not_accepted');
			expect(res.body.field).toBe(field);
		}

		// Enable passkeys + campaign, then try turning passkeys off -> 409
		const on = await adminReq('PATCH', `/admin/api/projects/${id}`, pwdCookie, {
			passkeyLogin: true,
			passkeyRequired: true
		});
		expect(on.status).toBe(200);
		const offFail = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passkeyLogin: false
			}
		);
		expect(offFail.status).toBe(409);
		expect(offFail.body.field).toBe('passkeyLogin');

		// Turning both off together succeeds
		const offBoth = await adminReq(
			'PATCH',
			`/admin/api/projects/${id}`,
			pwdCookie,
			{
				passkeyLogin: false,
				passkeyRequired: false
			}
		);
		expect(offBoth.status).toBe(200);

		// Non-admin flags refused on ADMIN_BUCKET_ID with 422
		for (const field of [
			'passkeyRecovery',
			'passkeyRequired',
			'passkeyForFederated'
		] as const) {
			const res = await adminReq(
				'PATCH',
				`/admin/api/projects/${ADMIN_BUCKET_ID}`,
				pwdCookie,
				{ [field]: true }
			);
			expect(res.status).toBe(422);
			expect(res.body.field).toBe(field);
		}
	});

	it('allows turning passwords off on the administrators project with a passkey-authenticated super admin (Q3=A)', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, { passkeyLogin: true });
		await seedPasskey(ADMIN_BUCKET_ID, adminId);

		// Password-authenticated super admin is refused
		const byPwd = await adminReq(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			pwdCookie,
			{ passwordLogin: false }
		);
		expect(byPwd.status).toBe(409);

		// Passkey-authenticated super admin without mail is refused
		const pkCookie = await superCookie(
			adminId,
			configuration.acrMap.phishing_resistant
		);
		await mailOn(false);
		const noMail = await adminReq(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			pkCookie,
			{ passwordLogin: false }
		);
		expect(noMail.status).toBe(409);
		expect(String(noMail.body.message)).toContain('mail');

		// Readiness reports mailDeliveryConfigured
		await mailOn();
		const readiness = await adminReq(
			'GET',
			'/admin/api/admins/sign-in-readiness',
			pkCookie
		);
		expect(readiness.status).toBe(200);
		expect(readiness.body.mailDeliveryConfigured).toBe(true);

		// Preview then confirm with expect.withoutWayIn
		const preview = await adminReq(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			pkCookie,
			{ passwordLogin: false }
		);
		expect(preview.status).toBe(409);
		expect(preview.body.confirmationRequired).toBe(true);
		const expectCounts = preview.body.expect as Record<string, number>;
		expect(typeof expectCounts.withoutWayIn).toBe('number');

		const applied = await adminReq(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			pkCookie,
			{ passwordLogin: false, confirm: true, expect: expectCounts }
		);
		expect(applied.status).toBe(200);
		expect(applied.body.passwordLogin).toBe(false);
	});
});
