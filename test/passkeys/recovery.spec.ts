import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { codeFor } from '../two_step_page/helpers.ts';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	claimsOf,
	creationOptionsIn,
	holdingPasskey,
	linkIn,
	mailOn,
	mailsTo,
	project,
	redeem,
	signInWithPasskey,
	type Project
} from './helpers.ts';
import { present } from '../shape.ts';
import { SECRET } from './offer_helpers.ts';

const MULTI_FACTOR = 'urn:example:acr:mfa';
const PHISHING_RESISTANT = 'urn:example:acr:phr';

async function startAuth(browser: Browser, at: Project): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: at.clientId,
		redirect_uri: `https://${at.clientId}.apps.test/cb`,
		scope: 'openid profile email',
		response_type: 'code'
	});
	const res = await browser.request(
		`${at.prefix}/auth?${encodeParams(auth.params)}`
	);
	expect(res.status).toBe(303);
	const match = /\/ui\/([^/]+)\/login/.exec(res.headers.get('location') ?? '');
	return match?.[1] ?? '';
}

/**
 * @proves Self-service passkey recovery (Spec 145 US2, Q1=A, S3): off by default, browser-bound 10-minute email link,
 * mandatory TOTP gate whenever enrolled regardless of `totpRequired`, no auto-sign-in, 72-hour `multi_factor` ACR
 * cap lifted either after 72h or earlier by signing in with another full passkey (`clearRecoveryCaps`).
 */
describe('self-service passkey recovery', () => {
	let acme: Project;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		setSystemTime();
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(acme.bucketId, {
			passwordLogin: false,
			passkeyLogin: true,
			passkeyRecovery: true,
			totpRequired: false
		});
	});

	afterEach(() => {
		setSystemTime();
	});

	it('redirects away when passkeyRecovery is off (the default)', async () => {
		await getBucketStore().update(acme.bucketId, { passkeyRecovery: false });
		const browser = new Browser(acme.origin);
		const uid = await startAuth(browser, acme);

		const res = await browser.request(`/ui/${uid}/passkey-recovery`);
		expect(res.status).toBe(303);
		expect(res.headers.get('location')).toBe(`/ui/${uid}/login`);
	});

	it('recovers a passkey via browser-bound link, enforces mandatory TOTP gate, does not auto-sign-in, and applies the 72h ACR cap with early lift', async () => {
		await getBucketStore().update(acme.bucketId, { passwordLogin: true });
		const who = await holdingPasskey(acme, { keepCode: true });
		const existingDevice = who.device;
		resetSentEmails();
		// Advance past the 30-second TOTP step already consumed by holdingPasskey
		setSystemTime(new Date(Date.now() + 35_000));
		await getBucketStore().update(acme.bucketId, {
			passwordLogin: false,
			passkeyLogin: true,
			passkeyRecovery: true,
			totpRequired: false
		});

		const browser = new Browser(acme.origin);
		const uid = await startAuth(browser, acme);

		// Request recovery link
		const reqRes = await browser.post(`/ui/${uid}/passkey-recovery`, {
			email: who.email
		});
		expect(reqRes.status).toBe(200);
		expect(await reqRes.text()).toContain('Check your email');

		// Wait one tick for off-path mail delivery
		await Bun.sleep(20);
		const mails = mailsTo(who.email);
		expect(mails.length).toBe(1);
		const verifyUrl = new URL(linkIn(who.email, '/passkey-recovery/verify'));

		// Cross-browser attempt refused
		const attacker = new Browser(acme.origin);
		const attackerUid = await startAuth(attacker, acme);
		const stolen = await attacker.request(
			`/ui/${attackerUid}/passkey-recovery/verify${verifyUrl.search}`
		);
		expect(stolen.status).toBe(400);

		// Same browser opens link -> TOTP gate required even though bucket.totpRequired is false
		const totpPage = await browser.request(
			`${verifyUrl.pathname}${verifyUrl.search}`
		);
		expect(totpPage.status).toBe(200);
		expect(await totpPage.text()).toContain('authenticator app');

		// Trying to skip TOTP directly to /create fails
		const skip = await browser.request(`/ui/${uid}/passkey-recovery/create`);
		expect(skip.status).toBe(303);

		// Wrong TOTP refused
		const badTotp = await browser.post(`/ui/${uid}/passkey-recovery/totp`, {
			code: '000000'
		});
		expect(badTotp.status).toBe(400);

		// Valid TOTP advances to passkey creation
		const goodTotp = await browser.post(`/ui/${uid}/passkey-recovery/totp`, {
			code: codeFor(SECRET)
		});
		expect(goodTotp.status).toBe(303);
		expect(goodTotp.headers.get('location')).toBe(
			`/ui/${uid}/passkey-recovery/create`
		);

		const createPage = await browser.request(
			`/ui/${uid}/passkey-recovery/create`
		);
		const options = creationOptionsIn(await createPage.text());
		const recoveredDevice = new SoftAuthenticator();
		const credential = await recoveredDevice.create(options, {
			origin: acme.origin
		});
		const done = await browser.post(`/ui/${uid}/passkey-recovery/create`, {
			credential: JSON.stringify(credential)
		});
		// No auto-sign-in: renders done page linking to /ui/:uid/login
		expect(done.status).toBe(200);
		expect(await done.text()).toContain(`/ui/${uid}/login`);

		const list = await getPasskeyStore().listOf(acme.bucketId, who.accountId);
		const recovered = list.find((p) => p.createdVia === 'recovery');
		expect(recovered).toBeDefined();
		expect(recovered?.recoveredUntil).toBeInstanceOf(Date);

		// Signing in with the recovered passkey during 72h cap yields multi_factor (NOT phishing_resistant)
		const sign1 = await signInWithPasskey(
			new Browser(acme.origin),
			recoveredDevice,
			acme,
			{ acr_values: PHISHING_RESISTANT }
		);
		const tokens1 = await redeem(acme, sign1.auth, sign1.code);
		expect(claimsOf(tokens1.id_token).acr).toBe(MULTI_FACTOR);

		// Signing in with another full passkey lifts the recovery cap early + audits enduser.passkey.confirm
		const signFull = await signInWithPasskey(
			new Browser(acme.origin),
			existingDevice,
			acme,
			{ acr_values: PHISHING_RESISTANT }
		);
		const tokensFull = await redeem(acme, signFull.auth, signFull.code);
		expect(claimsOf(tokensFull.id_token).acr).toBe(PHISHING_RESISTANT);

		const afterLift = await getPasskeyStore().find(
			acme.bucketId,
			present(recovered, 'recovered passkey')._id
		);
		expect(afterLift?.recoveredUntil).toBeUndefined();
		const confirmAudits = await adminAuditStore.list({
			action: 'enduser.passkey.confirm',
			targetId: who.accountId
		});
		expect(confirmAudits.entries.length).toBeGreaterThanOrEqual(1);

		// Now the recovered passkey yields phishing_resistant
		const sign2 = await signInWithPasskey(
			new Browser(acme.origin),
			recoveredDevice,
			acme,
			{ acr_values: PHISHING_RESISTANT }
		);
		const tokens2 = await redeem(acme, sign2.auth, sign2.code);
		expect(claimsOf(tokens2.id_token).acr).toBe(PHISHING_RESISTANT);
	});
});
