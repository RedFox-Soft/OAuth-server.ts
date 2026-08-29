import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	adapter,
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { resetSentEmails, sentEmails } from '../mail_capture.ts';
import { TestAdapter } from 'test/models.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const PASSWORD = 'correct horse battery';
const INVALID_CODE = 'Invalid code';

let requiredBucketId: string;
let optionalBucketId: string;
let closedBucketId: string;

async function seedBucket(
	name: string,
	clientId: string,
	fields: Record<string, unknown>
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		...fields
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${clientId}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

async function startInteraction(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

async function postForm(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams(fields).toString(),
			redirect: 'manual'
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		location: res.headers.get('location'),
		setCookie: res.headers.get('set-cookie')
	};
}

async function getPage(path: string, cookie?: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		location: res.headers.get('location'),
		contentType: res.headers.get('content-type') ?? ''
	};
}

/*
 * The Base32 secret the enrolment page is offering, read out of the page's own props script — which is
 * exactly what an authenticator app would get from the QR beside it, and the only place a test can
 * legitimately learn it.
 */
function secretFrom(html: string): string {
	const props = /window\.PROPS=(\{.*?\})<\/script>/s.exec(html)?.[1];
	if (!props) throw new Error('the enrolment page carried no props script');
	const parsed = JSON.parse(props) as { secretText?: string };
	if (!parsed.secretText) throw new Error('the props carried no secret');
	return parsed.secretText.replace(/\s+/g, '');
}

function codeFor(secret: string, at = epochTime()): string {
	return hotp(decodeBase32(secret), stepFor(at));
}

async function register(clientId: string, email: string) {
	const { uid, cookie } = await startInteraction(clientId);
	const res = await postForm(`/ui/${uid}/registration`, cookie, {
		email,
		password: PASSWORD,
		confirmPassword: PASSWORD
	});
	return { uid, cookie, res };
}

describe('enrolment at registration (US2)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		resetSentEmails();
		requiredBucketId = await seedBucket('Enrol Required', 'totp-required-app', {
			totpRequired: true
		});
		optionalBucketId = await seedBucket('Enrol Optional', 'totp-optional-app', {
			totpRequired: false
		});
		closedBucketId = await seedBucket('Enrol Closed', 'totp-migrate-app', {
			totpRequired: true,
			registrationOpen: false
		});
	});

	it('sends a registrant into the enrolment step', async () => {
		const { uid, res } = await register(
			'totp-required-app',
			`enrol-${Math.random()}@x.io`
		);
		expect(res.status).toBe(303);
		expect(res.location).toBe(`/ui/${uid}/totp/enroll`);
	});

	it('offers a scannable QR and the same secret as text', async () => {
		const email = `qr-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);

		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		expect(page.status).toBe(200);
		expect(page.contentType).toContain('text/html');

		// An inline SVG, not a canvas: a canvas is empty until scripts run.
		expect(page.text).toContain('<svg');
		// The otpauth URI the QR encodes, carrying the issuer label and the account.
		expect(page.text).toContain('otpauth://totp/');
		expect(page.text).toContain(encodeURIComponent(email));

		// And the typed fallback, which is what a camera that will not focus comes down to.
		const secret = secretFrom(page.text);
		expect(secret).toMatch(/^[A-Z2-7]{32}$/);
	});

	it('records nothing against the account until a code proves possession', async () => {
		const email = `unproved-${Math.random()}@x.io`;
		await register('totp-required-app', email);

		const user = await getUserStore(requiredBucketId).findByEmail(email);
		expect(user).toBeTruthy();
		expect(user?.totp).toBeUndefined();
	});

	it('completes registration on a correct code', async () => {
		const email = `done-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		const secret = secretFrom(page.text);

		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secret)
		});
		expect(res.status).toBe(303);
		expect(res.setCookie ?? '').toContain('_session=');

		const user = await getUserStore(requiredBucketId).findByEmail(email);
		expect(user?.totp?.secret).toBe(secret);
		expect(user?.totp?.enrolledAt).toBeDefined();
	});

	/*
	 * The property that makes a mistyped digit survivable. A fresh secret on every wrong code would mean
	 * deleting and re-adding the entry in the authenticator app, which is why the pending record is keyed
	 * by the interaction rather than minted per request.
	 */
	it('re-offers the same secret after a wrong code', async () => {
		const email = `same-secret-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const first = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		const secret = secretFrom(first.text);

		const rejected = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: '000001'
		});
		expect(rejected.status).toBe(400);
		expect(rejected.text).toContain(INVALID_CODE);
		expect(secretFrom(rejected.text)).toBe(secret);

		// A reload offers it too, rather than rotating under the person mid-setup.
		const reloaded = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		expect(secretFrom(reloaded.text)).toBe(secret);

		// And the secret that was on screen all along is the one that works.
		const accepted = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secret)
		});
		expect(accepted.status).toBe(303);
	});

	it('leaves an abandoned enrolment unable to sign in with the password alone', async () => {
		const email = `abandoned-${Math.random()}@x.io`;
		await register('totp-required-app', email);

		// A completely fresh sign-in, as if they closed the tab and came back later.
		const { uid, cookie } = await startInteraction('totp-required-app');
		const res = await postForm(`/ui/${uid}/login`, cookie, {
			username: email,
			password: PASSWORD
		});
		expect(res.status).toBe(303);
		expect(res.location).toBe(`/ui/${uid}/totp/enroll`);
		expect(res.setCookie ?? '').not.toContain('_session=');
	});

	it('signs the person in with two factors recorded', async () => {
		const email = `amr-enrol-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);

		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secretFrom(page.text))
		});
		expect(res.location ?? '').toMatch(/\/consent$|\/callback/);
	});

	it('destroys the pending record once it is confirmed', async () => {
		const email = `cleanup-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		expect(await adapter('TotpEnrollment').find(uid)).toBeDefined();

		await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secretFrom(page.text))
		});
		expect(await adapter('TotpEnrollment').find(uid)).toBeUndefined();
	});

	it('offers a fresh secret once the pending one has expired', async () => {
		const email = `expired-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const first = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		const secret = secretFrom(first.text);

		/*
		 * Age the live record, which is exactly the state MongoDB's lazy TTL monitor leaves behind — an
		 * expired document still findable for up to a minute. Written through `syncUpdate` because the
		 * front door refuses it: `TestAdapter.upsert` asserts the written `exp` matches the TTL it was
		 * given, so an inconsistent record cannot be forged that way.
		 */
		TestAdapter.for('TotpEnrollment').syncUpdate(uid, {
			exp: epochTime() - 1
		});

		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secret)
		});
		expect(res.status).toBe(303);
		expect(res.location).toBe(`/ui/${uid}/totp/enroll`);

		const reoffered = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		expect(secretFrom(reoffered.text)).not.toBe(secret);
	});

	/*
	 * Same race on the enrolment side. Confirming must not report success against a deleted row: the
	 * caller would write `result.login` and sign someone in as an account that holds no authenticator
	 * and, in fact, does not exist.
	 */
	it('refuses to enrol an account that vanished before the code was confirmed', async () => {
		const email = `vanishing-enrol-${Math.random()}@x.io`;
		const { uid, cookie } = await register('totp-required-app', email);
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		const secret = secretFrom(page.text);

		const user = await getUserStore(requiredBucketId).findByEmail(email);
		await getUserStore(requiredBucketId).destroy(user!._id);

		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secret)
		});

		expect(res.setCookie ?? '').not.toContain('_session=');
		expect(res.location).toBe(`/ui/${uid}/login`);
		// The pending secret is not left addressed to a row that no longer exists.
		expect(await adapter('TotpEnrollment').find(uid)).toBeUndefined();
	});

	it('sends someone with no half-finished sign-in back to the login page', async () => {
		const { uid, cookie } = await startInteraction('totp-required-app');
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		expect(page.status).toBe(303);
		expect(page.location).toBe(`/ui/${uid}/login`);
	});

	it('generates no secret for a bucket that has closed registration', async () => {
		const email = `closed-${Math.random()}@x.io`;
		const { uid, res } = await register('totp-migrate-app', email);
		expect(res.status).toBe(403);
		expect(await adapter('TotpEnrollment').find(uid)).toBeUndefined();
		expect(await getUserStore(closedBucketId).findByEmail(email)).toBeNull();
	});

	describe('a bucket that does not require the second factor', () => {
		it('registers exactly as it did before, with no enrolment step', async () => {
			const email = `plain-${Math.random()}@x.io`;
			const { uid, res } = await register('totp-optional-app', email);
			expect(res.status).toBe(303);
			expect(res.location).toBe(`/ui/${uid}/login`);

			const user = await getUserStore(optionalBucketId).findByEmail(email);
			expect(user).toBeTruthy();
			expect(user?.totp).toBeUndefined();
			expect(await adapter('TotpEnrollment').find(uid)).toBeUndefined();
		});
	});

	describe('composed with email verification', () => {
		let bothBucketId: string;

		beforeAll(async () => {
			bothBucketId = await seedBucket('Both', 'totp-admin-app', {
				totpRequired: true,
				emailVerificationRequired: true,
				verificationMethod: 'link'
			});
		});

		/*
		 * Verification runs first and keeps its own redirect, so the two requirements compose rather than
		 * one replacing the other: the address is proved now, the authenticator at the first sign-in.
		 */
		it('sends the verification mail and keeps its redirect', async () => {
			const email = `both-${Math.random()}@x.io`;
			const before = sentEmails.length;
			const { uid, res } = await register('totp-admin-app', email);

			expect(sentEmails.length).toBe(before + 1);
			expect(res.location).toContain(`/ui/${uid}/login`);

			const user = await getUserStore(bothBucketId).findByEmail(email);
			expect(user?.verified).toBe(false);
			expect(user?.totp).toBeUndefined();
		});
	});
});
