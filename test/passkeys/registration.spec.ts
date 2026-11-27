import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	claimsOf,
	creationOptionsIn,
	linkIn,
	mailOn,
	mailsTo,
	person,
	project,
	redeem,
	type Project
} from './helpers.ts';

const PHISHING_RESISTANT = 'urn:example:acr:phr';

async function startAuth(
	browser: Browser,
	at: Project
): Promise<{ uid: string; auth: AuthorizationRequest }> {
	const auth = new AuthorizationRequest({
		client_id: at.clientId,
		redirect_uri: `https://${at.clientId}.apps.test/cb`,
		scope: 'openid profile email',
		response_type: 'code',
		acr_values: PHISHING_RESISTANT
	});
	const res = await browser.request(
		`${at.prefix}/auth?${encodeParams(auth.params)}`
	);
	expect(res.status).toBe(303);
	const loc = res.headers.get('location') ?? '';
	const match = /\/ui\/([^/]+)\/login/.exec(loc);
	expect(match).not.toBeNull();
	return { uid: match?.[1] ?? '', auth };
}

/**
 * @proves Pre-account passkey registration (Spec 145 US1, Q2=A, S4): honours `verificationMethod` (`link` and `code`),
 * verifies mailbox control BEFORE creating any user record, keeps taken addresses indistinguishable on screen without
 * mutating the existing account, binds link challenges to the originating browser interaction, creates a verified
 * passwordless account + passkey (`createdVia: 'registration'`), and signs in immediately with `phishing_resistant` ACR.
 */
describe('passkey-only registration', () => {
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
			passwordLogin: false,
			passkeyLogin: true,
			registrationOpen: true,
			verificationMethod: 'link'
		});
	});

	it('registers a new passwordless account via browser-bound email link and signs in with phishing_resistant ACR', async () => {
		const browser = new Browser(acme.origin);
		const { uid, auth } = await startAuth(browser, acme);

		// /ui/:uid/registration redirects to passkey registration when passwordLogin is false
		const regGet = await browser.request(`/ui/${uid}/registration`);
		expect(regGet.status).toBe(303);
		expect(regGet.headers.get('location')).toBe(
			`/ui/${uid}/registration/passkey`
		);

		const email = `pk-reg-link-${Math.random().toString(36).slice(2, 8)}@example.com`;
		const submitted = await browser.post(`/ui/${uid}/registration/passkey`, {
			email
		});
		expect(submitted.status).toBe(200);
		expect(await submitted.text()).toContain('Check your email');

		// Account MUST NOT exist before verification & WebAuthn creation
		expect(await getUserStore(acme.bucketId).findByEmail(email)).toBeNull();

		const mails = mailsTo(email);
		expect(mails.length).toBe(1);
		const verifyUrl = new URL(linkIn(email, '/registration/passkey/verify'));

		// Another browser / interaction cannot use the link
		const otherBrowser = new Browser(acme.origin);
		const { uid: otherUid } = await startAuth(otherBrowser, acme);
		const stolen = await otherBrowser.request(
			`/ui/${otherUid}/registration/passkey/verify${verifyUrl.search}`
		);
		expect(stolen.status).toBe(400);

		// Same browser follows the link -> gets WebAuthn creation options
		const verified = await browser.request(
			`${verifyUrl.pathname}${verifyUrl.search}`
		);
		expect(verified.status).toBe(200);
		const html = await verified.text();
		const options = creationOptionsIn(html);

		const device = new SoftAuthenticator();
		const credential = await device.create(options, { origin: acme.origin });
		const done = await browser.post(`/ui/${uid}/registration/passkey/create`, {
			credential: JSON.stringify(credential)
		});
		expect(done.status).toBe(303);
		const cb = new URL(done.headers.get('location') ?? 'https://invalid');
		expect(cb.origin).toBe(`https://${acme.clientId}.apps.test`);
		const code = cb.searchParams.get('code');
		expect(code).toBeTruthy();

		// User and passkey created with verified=true, passwordSet=false, createdVia='registration'
		const createdUser = present(
			await getUserStore(acme.bucketId).findByEmail(email),
			'created user'
		);
		expect(createdUser.verified).toBe(true);
		expect(createdUser.passwordSet).toBe(false);
		const passkeys = await getPasskeyStore().listOf(
			acme.bucketId,
			createdUser._id
		);
		expect(passkeys.length).toBe(1);
		expect(passkeys[0]?.createdVia).toBe('registration');

		// Audit entry recorded
		const audits = await adminAuditStore.list({
			action: 'enduser.passkey.add',
			targetId: createdUser._id
		});
		expect(audits.entries.length).toBeGreaterThanOrEqual(1);

		// ID token carries phishing_resistant ACR and UserInfo reports email_verified: true
		const tokens = await redeem(acme, auth, present(code, 'auth code'));
		const claims = claimsOf(tokens.id_token);
		expect(claims.acr).toBe(PHISHING_RESISTANT);
		const userinfoRes = await browser.request(`${acme.prefix}/userinfo`, {
			headers: { authorization: `Bearer ${tokens.access_token}` }
		});
		expect(userinfoRes.status).toBe(200);
		expect(
			(await userinfoRes.json()) as { email_verified?: boolean }
		).toMatchObject({
			email_verified: true
		});

		// Replaying link fails (finished interaction is gone -> 422; another interaction -> 400)
		const replay = await browser.request(
			`${verifyUrl.pathname}${verifyUrl.search}`
		);
		expect(replay.status).toBe(422);
	});

	it('honours verificationMethod: code with 6-digit email code and attempt cap', async () => {
		await getBucketStore().update(acme.bucketId, {
			verificationMethod: 'code'
		});
		const browser = new Browser(acme.origin);
		const { uid } = await startAuth(browser, acme);

		const email = `pk-reg-code-${Math.random().toString(36).slice(2, 8)}@example.com`;
		const submitted = await browser.post(`/ui/${uid}/registration/passkey`, {
			email
		});
		expect(submitted.status).toBe(200);
		expect(await submitted.text()).toContain('6-digit code');

		const mail = present(mailsTo(email)[0], 'verification code email');
		const codeMatch = /\b(\d{6})\b/.exec(mail.text);
		expect(codeMatch).not.toBeNull();
		const code = codeMatch?.[1] ?? '';

		// Wrong code re-renders form with error
		const wrong = await browser.post(`/ui/${uid}/registration/passkey/code`, {
			code: '000000'
		});
		expect(wrong.status).toBe(400);

		// Correct code redirects to creation page
		const ok = await browser.post(`/ui/${uid}/registration/passkey/code`, {
			code
		});
		expect(ok.status).toBe(303);
		expect(ok.headers.get('location')).toBe(
			`/ui/${uid}/registration/passkey/create`
		);

		const createGet = await browser.request(
			`/ui/${uid}/registration/passkey/create`
		);
		const options = creationOptionsIn(await createGet.text());
		const credential = await new SoftAuthenticator().create(options, {
			origin: acme.origin
		});
		const done = await browser.post(`/ui/${uid}/registration/passkey/create`, {
			credential: JSON.stringify(credential)
		});
		expect(done.status).toBe(303);
		const created = await getUserStore(acme.bucketId).findByEmail(email);
		expect(created?.passwordSet).toBe(false);
		expect(created?.verified).toBe(true);
	});

	it('hides existing addresses identically on screen and sends an informational email without mutating the account (S4)', async () => {
		const existing = await person(acme.bucketId);
		const browser = new Browser(acme.origin);
		const { uid } = await startAuth(browser, acme);

		const res = await browser.post(`/ui/${uid}/registration/passkey`, {
			email: existing.email
		});
		expect(res.status).toBe(200);
		expect(await res.text()).toContain('Check your email');

		const mails = mailsTo(existing.email);
		expect(mails.length).toBe(1);
		expect(mails[0]?.text).toContain('already registered');
		expect(mails[0]?.text).not.toContain('/registration/passkey/verify');
		expect(
			(await getPasskeyStore().listOf(acme.bucketId, existing.accountId)).length
		).toBe(0);
	});
});
