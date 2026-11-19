import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { destroyBucket } from 'lib/admin/buckets/destroy.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { request as requestPasswordReset } from 'lib/password_reset/challenge.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { present } from '../shape.ts';
import {
	ACME,
	BETA,
	Browser,
	SUB,
	holdingPasskey,
	linkIn,
	mailOn,
	presentedAt,
	project,
	securityPage,
	signInWithPasskey,
	signedIn,
	signedInWithPasskey,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;
let cookie: string;

/* One call of the console's API, as a super administrator. */
async function admin(
	method: string,
	path: string,
	body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		json: text ? (JSON.parse(text) as Record<string, unknown>) : {}
	};
}

function userPath(at: Project, accountId: string): string {
	return `/admin/api/projects/${at.bucketId}/users/${accountId}`;
}

async function signsIn(
	at: Project,
	device: Parameters<typeof signInWithPasskey>[1]
) {
	const { code } = await signInWithPasskey(new Browser(at.origin), device, at);
	return code;
}

async function count(at: Project, accountId: string): Promise<number> {
	return getPasskeyStore().countOf(at.bucketId, accountId);
}

/* A password reset by the link mailed to the person, completed in a browser as they would. */
async function resetPassword(at: Project, email: string): Promise<void> {
	resetSentEmails();
	const asked = await requestPasswordReset(email, at.bucketId);
	expect(asked.ok).toBe(true);
	const link = linkIn(email, '/reset-password');
	const token = present(new URL(link).searchParams.get('token'), 'a token');
	const done = await new Browser(at.origin).post(new URL(link).pathname, {
		token,
		password: 'a-new-password-for-sure',
		confirmPassword: 'a-new-password-for-sure'
	});
	expect(done.status).toBe(200);
}

/**
 * @proves A passkey lasts as long as its account and no longer: it signs in again after a lock and unlock, a
 * deactivation and reactivation, a sign-out everywhere and a password reset of a confirmed account; it is gone with
 * a person deleted in the console or in bulk, with a destroyed project, and with an unconfirmed account's completed
 * reset; and after the project moves to another site it is listed as made for the old address and refused.
 */
describe('how long a passkey lasts', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	describe('kept', () => {
		it('signs in after the account is locked and unlocked', async () => {
			const { device, accountId } = await holdingPasskey(acme);
			const locked = await admin('POST', `${userPath(acme, accountId)}/lock`, {
				reason: 'looking into it'
			});
			expect(locked.status).toBe(200);
			expect((await presentedAt(acme, device)).status).toBe(400);
			await admin('POST', `${userPath(acme, accountId)}/unlock`, {});

			expect(await signsIn(acme, device)).toBeString();
		});

		it('signs in after the account is deactivated and reactivated', async () => {
			const { device, accountId } = await holdingPasskey(acme);
			const off = await admin('PATCH', userPath(acme, accountId), {
				active: false
			});
			expect(off.status).toBe(200);
			await admin('PATCH', userPath(acme, accountId), { active: true });

			expect(await signsIn(acme, device)).toBeString();
		});

		it('signs in after the person signs out everywhere', async () => {
			const { device } = await holdingPasskey(acme);
			const browser = await signedInWithPasskey(acme, device);
			const confirm = await browser.request(
				`${acme.prefix}/account/sign-ins?confirm=1`
			);
			const signedOut = await browser.post(`${acme.prefix}/account/sign-ins`, {
				xsrf: xsrfFrom(await confirm.text())
			});
			expect(signedOut.status).toBe(200);

			expect(await signsIn(acme, device)).toBeString();
		});

		it('signs in after a password reset of an account whose address is confirmed', async () => {
			const { device, email } = await holdingPasskey(acme);

			await resetPassword(acme, email);

			expect(await signsIn(acme, device)).toBeString();
		});
	});

	describe('removed', () => {
		it('goes with a person deleted in the console', async () => {
			const { accountId } = await holdingPasskey(acme);

			const deleted = await admin('DELETE', userPath(acme, accountId));

			expect(deleted.status).toBe(200);
			expect(await count(acme, accountId)).toBe(0);
		});

		it('goes with people deleted in bulk', async () => {
			const { accountId } = await holdingPasskey(acme);

			await admin(
				'POST',
				`/admin/api/projects/${acme.bucketId}/users/bulk/delete`,
				{ userIds: [accountId] }
			);

			expect(await count(acme, accountId)).toBe(0);
		});

		it('goes with a destroyed project', async () => {
			const doomed = await project(BETA);
			const { accountId } = await holdingPasskey(doomed);
			const scheduled = present(
				await getBucketStore().scheduleDeletion(doomed.bucketId, {
					scheduledAt: new Date(),
					purgeAt: new Date(),
					scheduledBy: { userId: 'test' }
				}),
				'a scheduled project'
			);

			const outcome = await destroyBucket(
				scheduled,
				{ kind: 'server' },
				{ due: false }
			);

			expect(outcome.claimed).toBe(true);
			expect(await count(doomed, accountId)).toBe(0);
		});

		it('goes when an account whose address was never confirmed is reset by mailed link', async () => {
			const { accountId, email } = await holdingPasskey(acme);
			await getUserStore(acme.bucketId).update(accountId, { verified: false });

			await resetPassword(acme, email);

			expect(await count(acme, accountId)).toBe(0);
		});
	});

	describe('after the project moves to another site', () => {
		let moved: Project;
		let device: Parameters<typeof signInWithPasskey>[1];
		let who: { email: string; accountId: string };

		beforeAll(async () => {
			resetSentEmails();
			await mailOn();
			const moving = await project(SUB);
			await getBucketStore().update(moving.bucketId, { displayName: 'Subway' });
			const held = await holdingPasskey(moving);
			device = held.device;
			who = { email: held.email, accountId: held.accountId };
			const path = `/admin/api/projects/${moving.bucketId}/address`;
			const preview = await admin('POST', path, {
				slug: 'sub',
				addressForm: 'subdomain'
			});
			expect(preview.status).toBe(409);
			const done = await admin('POST', path, {
				slug: 'sub',
				addressForm: 'subdomain',
				confirm: true,
				expect: preview.json.expect
			});
			expect(done.status).toBe(200);
			forgetBucketAddresses();
			moved = { ...moving, prefix: '', origin: 'http://sub.e.ly' };
		});

		it('lists the passkey as made for an old address', async () => {
			const { browser } = await signedIn(moved, 'password', who);

			const shown = textOf(
				await (await browser.request(securityPage(moved))).text()
			);

			expect(shown).toContain(
				'Made for an old address of Subway; it no longer works'
			);
		});

		it('refuses the passkey at the new address', async () => {
			/* A browser offers no passkey of another site; a forged presentation of it is what reaches the door. */
			const { credentialId } = present(
				(await getPasskeyStore().listOf(moved.bucketId, who.accountId))[0],
				'the passkey'
			);
			const refused = await presentedAt(moved, device, {
				choices: { credentialId }
			});

			expect(refused.status).toBe(400);
			expect(await count(moved, who.accountId)).toBe(1);
		});
	});
});
