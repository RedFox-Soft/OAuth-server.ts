import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { getBucketStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { shaped } from 'test/shape.ts';
import {
	Browser,
	amrOf,
	codeFor,
	codeOf,
	seedBucket,
	seedUser,
	signIn,
	uidOf,
	PASSWORD
} from './flow.ts';

let plainBucketId: string;
let mfaBucketId: string;
let switchBucketId: string;

function request(clientId: string, extra: Record<string, string> = {}) {
	return new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		...extra
	});
}

/* The secret the enrolment page offers, as the person would copy it into an authenticator. */
async function enrolmentSecret(browser: Browser, uid: string) {
	const page = await browser.request(`/ui/${uid}/totp/enroll`);
	const props = /window\.PROPS=(\{.*?\})<\/script>/s.exec(
		await page.text()
	)?.[1];
	if (!props) throw new Error('the enrolment page carried no props script');
	const { secretText } = shaped(
		Type.Object({ secretText: Type.String() }),
		JSON.parse(props)
	);
	return secretText.replace(/\s+/g, '');
}

/**
 * @proves A relying party reads in the ID token which authentication methods the sign-in actually
 * used — a password, or a password and a one-time code — and is never told of a method that was not
 * used, whether by a later password-only sign-in or by a session it did not itself establish.
 */
describe('the authentication methods an ID token reports', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'amr' });
		resetAdminMemoryStores();
		plainBucketId = await seedBucket('AMR plain', ['amr-app']);
		mfaBucketId = await seedBucket(
			'AMR mfa',
			['amr-mfa-app', 'amr-mfa-second-app', 'amr-tv'],
			{ totpRequired: true }
		);
		switchBucketId = await seedBucket('AMR switch', ['amr-switch-app'], {
			totpRequired: true
		});
	});

	it('carries pwd, otp and mfa after a sign-in with a password and a one-time code', async () => {
		const email = await seedUser(mfaBucketId, { enrolled: true });
		const auth = request('amr-mfa-app');

		const code = await signIn(new Browser(), auth, email, { second: true });

		expect(amrOf(await auth.getToken(code))).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('carries pwd, otp and mfa after a sign-in that enrols the second factor', async () => {
		const email = await seedUser(mfaBucketId);
		const auth = request('amr-mfa-app');
		const browser = new Browser();
		const started = await browser.authorize(auth);
		const uid = uidOf(started.headers.get('location'));
		await browser.post(`/ui/${uid}/login`, {
			username: email,
			password: PASSWORD
		});
		const secret = await enrolmentSecret(browser, uid);

		const enrolled = await browser.post(`/ui/${uid}/totp/enroll`, {
			code: codeFor(secret)
		});

		const token = await auth.getToken(codeOf(enrolled.headers.get('location')));
		expect(amrOf(token)).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('carries only pwd after a password-only sign-in', async () => {
		const email = await seedUser(plainBucketId);
		const auth = request('amr-app');

		const code = await signIn(new Browser(), auth, email);

		// Neither `otp` nor `mfa`: a relying party is never told of a factor nobody presented.
		expect(amrOf(await auth.getToken(code))).toEqual(['pwd']);
	});

	it('carries only the methods of the new sign-in after a re-authentication without the second factor', async () => {
		const email = await seedUser(switchBucketId, { enrolled: true });
		const browser = new Browser();
		await signIn(browser, request('amr-switch-app'), email, { second: true });
		// A second factor is demanded by the bucket, not by enrolment, so this is the only way one
		// session sees a two-factor sign-in followed by a password-only one.
		await getBucketStore().update(switchBucketId, { totpRequired: false });
		const again = request('amr-switch-app', { prompt: 'login' });

		const code = await signIn(browser, again, email);

		expect(amrOf(await again.getToken(code))).toEqual(['pwd']);
	});

	it('carries the session’s methods when a second relying party is signed in from an existing session', async () => {
		const email = await seedUser(mfaBucketId, { enrolled: true });
		const browser = new Browser();
		await signIn(browser, request('amr-mfa-app'), email, { second: true });
		const second = request('amr-mfa-second-app');

		const res = await browser.authorize(second);

		const token = await second.getToken(codeOf(res.headers.get('location')));
		expect(amrOf(token)).toEqual(['mfa', 'otp', 'pwd']);
	});
});
