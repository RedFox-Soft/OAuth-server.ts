import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { request as requestPasswordReset } from 'lib/password_reset/challenge.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	claimsOf,
	codeAfter,
	latestMail,
	linkIn,
	mailOn,
	person,
	postPasskey,
	project,
	redeem,
	securityPage,
	signInPage,
	signInWithPasskey,
	signedInWithPasskey,
	xsrfFrom,
	type Project
} from './helpers.ts';
import {
	SECRET,
	atOffer,
	createAtOffer,
	holdsCode,
	leaveOffer,
	offerIn,
	passwordSignIn
} from './offer_helpers.ts';
import { codeFor } from '../two_step_page/helpers.ts';

const PASSWORD_CONTEXT = 'urn:example:acr:pwd';
const MULTI_FACTOR = 'urn:example:acr:mfa';

let acme: Project;
let cookie: string;

/*
 * A person with a password and no authenticator app who accepted the offer after a password sign-in: their device now
 * holds a conditional passkey, and `browser` is the one that made it, signed in.
 */
async function conditionalHeld(): Promise<{
	email: string;
	accountId: string;
	device: SoftAuthenticator;
	browser: Browser;
}> {
	const { email, accountId } = await person(acme.bucketId);
	const landed = await passwordSignIn(acme, email);
	expect(atOffer(landed)).toBe(true);
	const device = new SoftAuthenticator();
	const created = await createAtOffer(acme, landed, device);
	expect(offerIn(await created.text())).toMatchObject({
		state: 'created',
		conditional: true
	});
	await leaveOffer(landed, 'continue');
	return { email, accountId, device, browser: landed.browser };
}

/* The ID token's context and sorted methods, for the sign-in a code was issued for. */
async function contextOf(
	at: Project,
	signIn: { auth: Parameters<typeof redeem>[1]; code: string }
): Promise<{ acr: unknown; amr: unknown }> {
	const claims = claimsOf(
		(await redeem(at, signIn.auth, signIn.code)).id_token
	);
	return {
		acr: claims.acr,
		amr: Array.isArray(claims.amr) ? claims.amr.map(String).sort() : claims.amr
	};
}

async function passkeysOf(accountId: string) {
	return getPasskeyStore().listOf(acme.bucketId, accountId);
}

/* The person's account page, as a form posts to it, with the page's own anti-forgery value. */
async function postOnPage(
	browser: Browser,
	fields: Record<string, string>
): Promise<Response> {
	const page = await (await browser.request(securityPage(acme))).text();
	return browser.post(securityPage(acme), { ...fields, xsrf: xsrfFrom(page) });
}

/* A password reset by the link mailed to the person, completed in a browser as they would. */
async function resetPassword(email: string): Promise<Response> {
	resetSentEmails();
	const asked = await requestPasswordReset(email, acme.bucketId);
	expect(asked.ok).toBe(true);
	const link = linkIn(email, '/reset-password');
	return new Browser(acme.origin).post(new URL(link).pathname, {
		token: present(new URL(link).searchParams.get('token'), 'a token'),
		password: 'a-new-password-for-sure',
		confirmPassword: 'a-new-password-for-sure'
	});
}

/**
 * @proves A passkey made at the offer after a password alone is conditional: it signs in without the password but only
 * as the password does, followed by the code step wherever a password would be, satisfying no requirement of two-step
 * sign-in and opening nothing on the person's page that a password alone does not. Whatever ends trust in the password
 * ends it: a reset by mail or by an administrator, and "This wasn't me", which also keeps the offer away until the
 * password is reset. The operator and the agent see it as unconfirmed.
 */
describe('a passkey made after a password alone', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		cookie = await cookieFor(await createAdministrator('super'));
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		await bindClientToBucket('acme-billing', acme.bucketId);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(acme.bucketId, {
			passkeyLogin: true,
			totpRequired: false
		});
	});

	afterEach(() => {
		setSystemTime();
	});

	it('is stored as conditional and mailed with "Yes, this was me" and "This wasn’t me"', async () => {
		const { email, accountId } = await conditionalHeld();

		expect(
			(await passkeysOf(accountId)).map((p) => [p.createdVia, p.conditional])
		).toEqual([['password', true]]);
		const mail = latestMail(email).text;
		expect(mail).toContain('/account/security/passkey-confirm?token=');
		expect(mail).toContain('/account/security/passkey-disown?token=');
		expect(mail).toContain('works like your password until you confirm it');
	});

	it('leaves the sign-in it was made in a password sign-in', async () => {
		const { email } = await person(acme.bucketId);
		const landed = await passwordSignIn(acme, email);
		await createAtOffer(acme, landed, new SoftAuthenticator());

		const code = await leaveOffer(landed, 'continue');

		expect(await contextOf(acme, { auth: landed.auth, code })).toEqual({
			acr: PASSWORD_CONTEXT,
			amr: ['pwd']
		});
	});

	it('signs in without the password, reported as a password sign-in with the passkey’s methods', async () => {
		const { device } = await conditionalHeld();

		const signIn = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme
		);

		expect(await contextOf(acme, signIn)).toEqual({
			acr: PASSWORD_CONTEXT,
			amr: ['pop', 'user']
		});
	});

	it('is followed by the code step for a person who holds an authenticator app, and then counts as two-step', async () => {
		const { accountId, device } = await conditionalHeld();
		await holdsCode(acme, accountId);
		setSystemTime(new Date(Date.now() + 60 * 1000));
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const posted = await postPasskey(browser, device, acme, page);

		const asked = new URL(
			present(posted.headers.get('location'), 'the code step'),
			page.url
		).toString();
		expect(asked).toMatch(/\/totp$/);
		const answered = await browser.post(asked, { code: codeFor(SECRET) });
		const code = await codeAfter(browser, answered, asked);
		expect(await contextOf(acme, { auth: page.auth, code })).toEqual({
			acr: MULTI_FACTOR,
			amr: ['mfa', 'otp', 'pop', 'user']
		});
	});

	it('is followed by setting up an authenticator app in a project that requires one', async () => {
		const { device } = await conditionalHeld();
		await getBucketStore().update(acme.bucketId, { totpRequired: true });
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const posted = await postPasskey(browser, device, acme, page);

		expect(posted.headers.get('location')).toMatch(/\/totp\/enroll$/);
	});

	it('is shown to the operator as unconfirmed, made after a password alone', async () => {
		const { accountId } = await conditionalHeld();

		const response = await elysia.handle(
			new Request(
				`http://e.ly/admin/api/projects/${acme.bucketId}/users/${accountId}/passkeys`,
				{ headers: { cookie } }
			)
		);

		const body: unknown = await response.json();
		expect(body).toMatchObject({
			passkeys: [{ createdVia: 'password', confirmed: false, state: 'works' }]
		});
		expect(JSON.stringify(body)).not.toContain('"confirm"');
	});

	describe('someone who knows only the password', () => {
		it('is asked for a code by an app that requires two-step sign-in', async () => {
			const { device } = await conditionalHeld();
			const billing = { ...acme, clientId: 'acme-billing' };
			const browser = new Browser(acme.origin);
			const page = await signInPage(browser, billing);

			const posted = await postPasskey(browser, device, acme, page);

			const landed = await browser.open(
				new URL(
					present(posted.headers.get('location'), 'a redirect'),
					page.url
				).toString()
			);
			expect(landed.url).toMatch(/\/code-required$/);
		});

		it('cannot add a passkey after signing in with it, without a mailed link', async () => {
			const { device } = await conditionalHeld();
			const browser = await signedInWithPasskey(acme, device);

			const html = await (await browser.request(securityPage(acme))).text();
			const started = await postOnPage(browser, { action: 'passkey_start' });

			expect(html).not.toContain('data-passkey-add');
			expect(started.headers.get('location') ?? '').toContain('/auth?');
		});

		it('cannot remove a passkey after signing in with it', async () => {
			const { accountId, device } = await conditionalHeld();
			const [held] = await passkeysOf(accountId);
			const browser = await signedInWithPasskey(acme, device);

			const started = await postOnPage(browser, {
				action: 'passkey_remove_start',
				passkey: present(held, 'the passkey')._id
			});

			expect(started.headers.get('location') ?? '').toContain('/auth?');
			expect((await passkeysOf(accountId)).length).toBe(1);
		});

		it('cannot confirm a passkey after signing in with it', async () => {
			const { accountId, device } = await conditionalHeld();
			const [held] = await passkeysOf(accountId);
			const browser = await signedInWithPasskey(acme, device);

			await postOnPage(browser, {
				action: 'passkey_confirm',
				passkey: present(held, 'the passkey')._id
			});

			expect((await passkeysOf(accountId))[0]?.conditional).toBe(true);
		});

		it('cannot set up an authenticator app after signing in with it, without a mailed link', async () => {
			const { device } = await conditionalHeld();
			const browser = await signedInWithPasskey(acme, device);

			const started = await postOnPage(browser, { action: 'start' });

			expect(started.headers.get('location') ?? '').toContain('/auth?');
		});

		it('still renames a passkey after signing in with it', async () => {
			const { accountId, device } = await conditionalHeld();
			const [held] = await passkeysOf(accountId);
			const browser = await signedInWithPasskey(acme, device);

			const renamed = await postOnPage(browser, {
				action: 'passkey_rename',
				passkey: present(held, 'the passkey')._id,
				name: 'Phone'
			});

			expect(renamed.headers.get('location')).toContain('done=passkey_renamed');
		});

		it('cannot make a silent passkey at an offer after a password alone', async () => {
			const { email, accountId } = await person(acme.bucketId);
			const landed = await passwordSignIn(acme, email);

			const refused = await createAtOffer(
				acme,
				landed,
				new SoftAuthenticator(),
				{
					silent: true,
					choices: { flags: { up: false, uv: false } }
				}
			);

			expect(refused.status).toBe(400);
			expect(await passkeysOf(accountId)).toEqual([]);
		});

		it('loses every conditional passkey, and keeps the full ones, to a password reset by mail', async () => {
			const { email, accountId } = await conditionalHeld();
			/* A full passkey of the same person beside it, as one added after a password and a code would be. */
			await getPasskeyStore().create({
				...present((await passkeysOf(accountId))[0], 'the passkey'),
				_id: 'full-passkey-of-the-owner',
				credentialId: 'ZnVsbC1wYXNza2V5LW9mLW93bmVy',
				createdVia: 'password_code',
				conditional: undefined,
				confirm: undefined
			});

			const done = await resetPassword(email);

			expect(done.status).toBe(200);
			expect(await done.text()).toContain(
				'Passkeys you had not confirmed were removed'
			);
			expect((await passkeysOf(accountId)).map((p) => p._id)).toEqual([
				'full-passkey-of-the-owner'
			]);
			const { entries } = await adminAuditStore.list({ targetId: accountId });
			expect(
				entries.find((entry) => entry.action === 'enduser.passkey.remove')
					?.cascade
			).toEqual({ passkeys: 1 });
		});

		it('loses every conditional passkey when an administrator sets a new password', async () => {
			const { accountId } = await conditionalHeld();

			const response = await elysia.handle(
				new Request(
					`http://e.ly/admin/api/projects/${acme.bucketId}/users/${accountId}/password`,
					{
						method: 'POST',
						headers: { cookie, 'content-type': 'application/json' },
						body: JSON.stringify({ password: 'a-new-password-for-sure' })
					}
				)
			);

			expect(response.status).toBe(200);
			expect(await passkeysOf(accountId)).toEqual([]);
		});

		it('loses every conditional passkey, and is offered none until a reset, after "This wasn’t me"', async () => {
			const { email, accountId } = await conditionalHeld();
			const disown = linkIn(email, '/account/security/passkey-disown');
			const owner = new Browser(acme.origin);
			await owner.request(disown);
			await owner.post(new URL(disown).pathname, {
				token: present(new URL(disown).searchParams.get('token'), 'a token')
			});
			expect(await passkeysOf(accountId)).toEqual([]);
			setSystemTime(new Date(Date.now() + 31 * 24 * 3600 * 1000));

			const held = await passwordSignIn(acme, email);
			await resetPassword(email);

			expect(atOffer(held)).toBe(false);
			expect(
				(await getUserStore(acme.bucketId).find(accountId))?.passkeyOffer?.held
			).toBeUndefined();
		});
	});
});
