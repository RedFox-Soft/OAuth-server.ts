import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import { Type } from '@sinclair/typebox';

import bootstrap, { encodeParams } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { codeFor } from '../two_step_page/helpers.ts';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	PASSWORD,
	propsIn,
	signInPage,
	claimsOf,
	latestMail,
	mailOn,
	mailsTo,
	person,
	project,
	redeem,
	seedPasskey,
	signInWithPasskey,
	holdingPasskey,
	type Project
} from './helpers.ts';
import {
	atOffer,
	createAtOffer,
	holdsCode,
	leaveOffer,
	offerIn,
	passwordSignIn
} from './offer_helpers.ts';

const MULTI_FACTOR = 'urn:example:acr:mfa';

/* A minute on: a second sign-in in the same half-minute would type the code just used, which is refused. */
function nextCode(): void {
	setSystemTime(new Date(Date.now() + 60 * 1000));
}

/* A person of the project with a password and an authenticator app: their sign-in is a password and a code. */
async function withCode(at: Project) {
	const who = await person(at.bucketId);
	await holdsCode(at, who.accountId);
	return who;
}

/**
 * @proves After a sign-in with a password and a code, on a device that can make a passkey, a person is offered one
 * before reaching the app; creating it there stores a passkey that counts as two-step sign-in, mails and records it
 * once, and the app still receives the sign-in the person made. Every showing keeps the offer away for thirty days,
 * "Don't ask again" appears from the second showing and ends it, and nothing is offered where it would be wrong advice:
 * after a provider or passkey sign-in, without "Remember me", on a device that cannot make one, after another page of
 * the sign-in, or where the project, the mail, the address or the person's own choice says no.
 */
describe('the passkey offer after a password sign-in', () => {
	let acme: Project;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(acme.bucketId, {
			passkeyLogin: true,
			passkeyOffer: undefined,
			totpRequired: false
		});
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('after a password and a code', () => {
		it('follows the code step on a device that can make a passkey, with "Remember me" ticked', async () => {
			const { email } = await withCode(acme);

			const landed = await passwordSignIn(acme, email);

			expect(atOffer(landed)).toBe(true);
			expect(offerIn(await landed.response.text())).toMatchObject({
				state: 'offer',
				email,
				silent: true,
				askNever: false
			});
		});

		it('stores a full passkey, mails it once and records it once when the person creates one', async () => {
			const { email, accountId } = await withCode(acme);
			const landed = await passwordSignIn(acme, email);

			const created = await createAtOffer(
				acme,
				landed,
				new SoftAuthenticator()
			);

			expect(created.status).toBe(200);
			expect(offerIn(await created.text()).state).toBe('created');
			const held = await getPasskeyStore().listOf(acme.bucketId, accountId);
			expect(held.map((p) => [p.createdVia, p.conditional])).toEqual([
				['password_code', undefined]
			]);
			expect(mailsTo(email).length).toBe(1);
			expect(latestMail(email).text).toContain('/passkey-disown?token=');
			expect(latestMail(email).text).not.toContain('/passkey-confirm?token=');
			const { entries } = await adminAuditStore.list({ targetId: accountId });
			expect(
				entries.filter((entry) => entry.action === 'enduser.passkey.add').length
			).toBe(1);
		});

		it('hands the app the sign-in the person made, not a passkey sign-in, after creating one', async () => {
			const { email } = await withCode(acme);
			const landed = await passwordSignIn(acme, email);
			await createAtOffer(acme, landed, new SoftAuthenticator());

			const code = await leaveOffer(landed, 'continue');

			const claims = claimsOf((await redeem(acme, landed.auth, code)).id_token);
			expect(claims.acr).toBe(MULTI_FACTOR);
			expect(
				Array.isArray(claims.amr) ? claims.amr.map(String).sort() : claims.amr
			).toEqual(['mfa', 'otp', 'pwd']);
		});

		it('takes the browser’s silent creation, without the device’s check, for a passkey full at once', async () => {
			const { email, accountId } = await withCode(acme);
			const landed = await passwordSignIn(acme, email);

			const created = await createAtOffer(
				acme,
				landed,
				new SoftAuthenticator(),
				{
					silent: true,
					choices: { flags: { up: false, uv: false } }
				}
			);

			expect(offerIn(await created.text()).state).toBe('created');
			expect(
				(await getPasskeyStore().listOf(acme.bucketId, accountId)).length
			).toBe(1);
		});

		it('signs in with the new passkey as two-step sign-in', async () => {
			const { email } = await withCode(acme);
			const landed = await passwordSignIn(acme, email);
			const device = new SoftAuthenticator();
			await createAtOffer(acme, landed, device);
			await leaveOffer(landed, 'continue');

			const { auth, code } = await signInWithPasskey(
				new Browser(acme.origin),
				device,
				acme
			);

			expect(claimsOf((await redeem(acme, auth, code)).id_token).acr).toBe(
				MULTI_FACTOR
			);
		});

		it('re-renders the offer without counting another showing when a create is refused', async () => {
			const { email, accountId } = await withCode(acme);
			const landed = await passwordSignIn(acme, email);
			const device = new SoftAuthenticator();
			await createAtOffer(acme, landed, device);
			/* The same ceremony a second time: it was spent by the first create. */
			const again = await createAtOffer(acme, landed, device);

			expect(again.status).toBe(400);
			expect(offerIn(await again.text())).toMatchObject({
				state: 'offer',
				refused: 'failed'
			});
			const user = present(
				await getUserStore(acme.bucketId).find(accountId),
				'the person'
			);
			expect(user.passkeyOffer?.shown).toBe(1);
		});
	});

	describe('the pause', () => {
		it('goes straight to the app after "Not now", and offers nothing for 30 days', async () => {
			const { email } = await withCode(acme);
			const first = await passwordSignIn(acme, email);
			expect(await leaveOffer(first, 'not_now')).toBeString();
			nextCode();

			const second = await passwordSignIn(acme, email);

			expect(atOffer(second)).toBe(false);
			expect(new URL(second.url).searchParams.get('code')).toBeString();
		});

		it('pauses the offer for a showing the person left without answering', async () => {
			const { email } = await withCode(acme);
			const first = await passwordSignIn(acme, email);
			expect(atOffer(first)).toBe(true);
			nextCode();

			const second = await passwordSignIn(acme, email);

			expect(atOffer(second)).toBe(false);
		});

		it('counts a reload of the offer as the same showing', async () => {
			const { email, accountId } = await withCode(acme);
			const first = await passwordSignIn(acme, email);

			const reloaded = await first.browser.request(first.url);

			expect(offerIn(await reloaded.text()).askNever).toBe(false);
			expect(
				(await getUserStore(acme.bucketId).find(accountId))?.passkeyOffer?.shown
			).toBe(1);
		});

		it('offers again after 30 days, with "Don’t ask again" at the second showing', async () => {
			const { email } = await withCode(acme);
			await passwordSignIn(acme, email);
			setSystemTime(new Date(Date.now() + 31 * 24 * 3600 * 1000));

			const second = await passwordSignIn(acme, email);

			expect(atOffer(second)).toBe(true);
			expect(offerIn(await second.response.text()).askNever).toBe(true);
		});

		it('never offers again after "Don’t ask again"', async () => {
			const { email } = await withCode(acme);
			await passwordSignIn(acme, email);
			setSystemTime(new Date(Date.now() + 31 * 24 * 3600 * 1000));
			const second = await passwordSignIn(acme, email);
			await leaveOffer(second, 'never');
			setSystemTime(new Date(Date.now() + 400 * 24 * 3600 * 1000));

			const later = await passwordSignIn(acme, email);

			expect(atOffer(later)).toBe(false);
		});
	});

	describe('no offer', () => {
		it('after a password sign-in with "Remember me" unticked', async () => {
			const { email } = await withCode(acme);

			expect(
				atOffer(await passwordSignIn(acme, email, { remember: false }))
			).toBe(false);
		});

		it('when the page found no device that can make a passkey', async () => {
			const { email } = await withCode(acme);

			expect(
				atOffer(await passwordSignIn(acme, email, { device: false }))
			).toBe(false);
		});

		it('after a passkey sign-in', async () => {
			const { device } = await holdingPasskey(acme, { keepCode: true });
			const browser = new Browser(acme.origin);

			const { code } = await signInWithPasskey(browser, device, acme);

			expect(code).toBeString();
		});

		it('after setting up an authenticator app during the sign-in', async () => {
			await getBucketStore().update(acme.bucketId, { totpRequired: true });
			const { email } = await person(acme.bucketId);
			const browser = new Browser(acme.origin);
			const page = await signInPage(browser, acme);
			const posted = await browser.post(page.url, {
				username: email,
				password: PASSWORD,
				remember: 'on',
				passkeyDevice: '1'
			});
			const enrol = new URL(
				present(posted.headers.get('location'), 'the enrolment'),
				page.url
			).toString();
			expect(enrol).toMatch(/\/totp\/enroll$/);
			const shown = shaped(
				Type.Object({ otpauthUri: Type.String() }),
				propsIn(await (await browser.request(enrol)).text())
			);
			const secret = present(
				new URL(shown.otpauthUri).searchParams.get('secret'),
				'the secret'
			);

			const answered = await browser.post(enrol, { code: codeFor(secret) });

			/* Setting one up was a page of its own: the sign-in goes on to the app, never to the offer. */
			const landed = await browser.open(
				new URL(
					present(answered.headers.get('location'), 'a resume'),
					enrol
				).toString()
			);
			expect(atOffer(landed)).toBe(false);
			expect(new URL(landed.url).searchParams.get('code')).toBeString();
		});

		it('when the instance cannot send mail', async () => {
			const { email } = await withCode(acme);
			await mailOn(false);

			expect(atOffer(await passwordSignIn(acme, email))).toBe(false);
		});

		it('when the person’s address is not confirmed', async () => {
			const { email, accountId } = await withCode(acme);
			await getUserStore(acme.bucketId).update(accountId, { verified: false });

			expect(atOffer(await passwordSignIn(acme, email))).toBe(false);
		});

		it('when the person already holds 20 passkeys', async () => {
			const { email, accountId } = await withCode(acme);
			for (let i = 0; i < 20; i++) await seedPasskey(acme.bucketId, accountId);

			expect(atOffer(await passwordSignIn(acme, email))).toBe(false);
		});

		it('when the project turned the offer off', async () => {
			const { email } = await withCode(acme);
			await getBucketStore().update(acme.bucketId, { passkeyOffer: false });

			expect(atOffer(await passwordSignIn(acme, email))).toBe(false);
		});

		it('when the project does not accept passkeys', async () => {
			const { email } = await withCode(acme);
			await getBucketStore().update(acme.bucketId, { passkeyLogin: false });

			expect(atOffer(await passwordSignIn(acme, email))).toBe(false);
		});

		it('for a request from a browser already signed in, which needs no page', async () => {
			const { email, accountId } = await withCode(acme);
			const first = await passwordSignIn(acme, email);
			await leaveOffer(first, 'not_now');
			/* The pause cleared, so only the absence of a sign-in on this request keeps the offer away. */
			await getUserStore(acme.bucketId).update(accountId, {
				passkeyOffer: undefined
			});
			const auth = new AuthorizationRequest({
				client_id: acme.clientId,
				scope: 'openid'
			});

			const landed = await first.browser.open(
				`${acme.origin}${acme.prefix}/auth?${encodeParams(auth.params)}`
			);

			expect(atOffer(landed)).toBe(false);
			expect(new URL(landed.url).searchParams.get('code')).toBeString();
		});
	});
});
