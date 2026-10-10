import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getUserStore,
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	sentEmails,
	resetSentEmails,
	lastEmail,
	emailsTo,
	extractVerifyUrl
} from '../mail_capture.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { present } from 'test/shape.js';
import { elysia } from 'lib/index.ts';

const CLIENT_ID = 'verify-link-app';
const PASSWORD = 'correct horse battery';

let bucketId: string;

// Drive a real authorization request so the provider prompts login and hands us an
// interaction uid + its `_interaction` cookie (same pattern as interactions_bucket.spec).
async function startInteraction() {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

async function register(email: string) {
	const { uid, cookie } = await startInteraction();
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie } }
		);
	return { uid, cookie, response };
}

async function login(uid: string, cookie: string, email: string) {
	const { response } = await agent
		.ui({ uid })
		.login.post(
			{ username: email, password: PASSWORD },
			{ headers: { cookie } }
		);
	return response.status;
}

/**
 * @proves A registrant proves their address by opening a single-use link in any browser, and a
 * closed bucket creates no account and sends no mail.
 */
describe('email verification — link method', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'link' });
		resetAdminMemoryStores();
		// A dedicated bucket (link method, verification required) reached by CLIENT_ID
		// through a project, so these specs never touch the shared 'redfox' bucket.
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Verify Link Bucket',
			emailVerificationRequired: true,
			verificationMethod: 'link'
		});
		bucketId = bucket._id;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Verify Link',
			slug: `verify-link-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: [CLIENT_ID]
		});
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('registers unverified and emails a verification link', async () => {
		const email = 'link-user@x.io';
		const { response } = await register(email);
		expect(response.status).toBe(303);
		const user = await getUserStore(bucketId).findByEmail(email);
		expect(user?.verified).toBe(false);
		expect(sentEmails.length).toBe(1);
		const url = extractVerifyUrl(present(lastEmail(), 'lastEmail()'));
		expect(url).toBeDefined();
	});

	it('verifies the account when the link is opened, then allows login', async () => {
		const email = 'link-verify@x.io';
		await register(email);
		const url = present(
			extractVerifyUrl(present(lastEmail(), 'lastEmail()')),
			'extractVerifyUrl(lastEmail())'
		);
		const token = present(
			new URL(url).searchParams.get('token'),
			"new URL(url).searchParams.get('token')"
		);

		// unverified → login refused
		const start = await startInteraction();
		expect(await login(start.uid, start.cookie, email)).toBe(400);

		const res = await agent['verify-email'].get({ query: { token } });
		expect(res.response.status).toBe(200);
		const user = await getUserStore(bucketId).findByEmail(email);
		expect(user?.verified).toBe(true);

		// verified → login succeeds (303 back into the auth pipeline)
		const start2 = await startInteraction();
		expect(await login(start2.uid, start2.cookie, email)).toBe(303);
	});

	it('sends a verification link, and says so, when an account that never received one signs in with the right password', async () => {
		// Created before its bucket required verification: no message was ever sent to it.
		const email = 'link-never-mailed@x.io';
		await getUserStore(bucketId).create(
			email,
			await Bun.password.hash(PASSWORD)
		);

		const { uid, cookie } = await startInteraction();
		const { response, error } = await agent
			.ui({ uid })
			.login.post(
				{ username: email, password: PASSWORD },
				{ headers: { cookie } }
			);

		expect(response.status).toBe(400);
		expect(JSON.stringify(error?.value)).toContain(
			'We sent a verification link'
		);
		expect(emailsTo(email)).toHaveLength(1);
		expect(extractVerifyUrl(present(lastEmail(), 'lastEmail()'))).toBeDefined();
	});

	it('sends nothing, and keeps the link already sent working, when a registrant signs in before following it', async () => {
		const email = 'link-signs-in-early@x.io';
		await register(email);
		const url = present(
			extractVerifyUrl(present(lastEmail(), 'lastEmail()')),
			'extractVerifyUrl(lastEmail())'
		);

		const start = await startInteraction();
		expect(await login(start.uid, start.cookie, email)).toBe(400);
		expect(emailsTo(email)).toHaveLength(1);

		const token = present(
			new URL(url).searchParams.get('token'),
			"new URL(url).searchParams.get('token')"
		);
		const res = await agent['verify-email'].get({ query: { token } });
		expect(res.response.status).toBe(200);
	});

	it('rejects an unknown or already-used token', async () => {
		const unknown = await agent['verify-email'].get({
			query: { token: 'not-a-real-token' }
		});
		expect(unknown.response.status).toBe(400);

		const email = 'link-reuse@x.io';
		await register(email);
		const token = present(
			new URL(
				present(
					extractVerifyUrl(present(lastEmail(), 'lastEmail()')),
					'extractVerifyUrl(lastEmail())'
				)
			).searchParams.get('token'),
			"new URL(extractVerifyUrl(lastEmail())).searchParams.get( 'token' )"
		);
		const first = await agent['verify-email'].get({ query: { token } });
		expect(first.response.status).toBe(200);
		// second use of the same token is refused (single-use)
		const second = await agent['verify-email'].get({ query: { token } });
		expect(second.response.status).toBe(400);
	});

	describe('sending the link again from the sign-in page', () => {
		async function resend(uid: string, cookie: string) {
			const res = await elysia.handle(
				new Request(`http://e.ly/ui/${uid}/verification/resend`, {
					method: 'POST',
					headers: { cookie }
				})
			);
			return {
				status: res.status,
				location: res.headers.get('location') ?? ''
			};
		}

		async function signInEarly(email: string) {
			await register(email);
			const start = await startInteraction();
			const { error } = await agent
				.ui({ uid: start.uid })
				.login.post(
					{ username: email, password: PASSWORD },
					{ headers: { cookie: start.cookie } }
				);
			return { ...start, page: JSON.stringify(error?.value) };
		}

		it('offers to send the link again when sign-in is refused for an unverified address', async () => {
			const { uid, page } = await signInEarly('link-offered-again@x.io');

			expect(page).toContain(`/ui/${uid}/verification/resend`);
		});

		it('sends a fresh link that verifies the address when the person who proved the password asks for it', async () => {
			const email = 'link-sent-again@x.io';
			const { uid, cookie } = await signInEarly(email);

			const res = await resend(uid, cookie);

			expect(res.status).toBe(303);
			expect(res.location).toBe(`/ui/${uid}/login?notice=verify_resent`);
			const mails = emailsTo(email);
			expect(mails).toHaveLength(2);
			const url = present(
				extractVerifyUrl(present(mails[1], 'second message')),
				'link'
			);
			const token = present(new URL(url).searchParams.get('token'), 'token');
			const opened = await agent['verify-email'].get({ query: { token } });
			expect(opened.response.status).toBe(200);
		});

		it('lands on the sign-in page saying a new link was sent, still offering to send it again', async () => {
			const { uid, cookie } = await signInEarly('link-lands-back@x.io');
			const { location } = await resend(uid, cookie);

			const page = await elysia.handle(
				new Request(`http://e.ly${location}`, { headers: { cookie } })
			);
			const html = await page.text();

			expect(page.status).toBe(200);
			expect(html).toContain('We sent you a new verification link');
			expect(html).toContain(`/ui/${uid}/verification/resend`);
		});

		it('sends nothing, and says a message went recently, when asked again within the cooldown', async () => {
			const email = 'link-sent-twice@x.io';
			const { uid, cookie } = await signInEarly(email);
			await resend(uid, cookie);

			const again = await resend(uid, cookie);

			expect(again.location).toBe(`/ui/${uid}/login?notice=verify_recent`);
			expect(emailsTo(email)).toHaveLength(2);
		});

		it('sends nothing for a sign-in that has not proved a password', async () => {
			const { uid, cookie } = await startInteraction();
			const before = sentEmails.length;

			const res = await resend(uid, cookie);

			expect(res.location).toBe(`/ui/${uid}/login`);
			expect(sentEmails.length).toBe(before);
		});
	});
});

describe('registration gating', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('rejects registration when the bucket is closed — no account, no email', async () => {
		const closed = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Closed Bucket',
			registrationOpen: false
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Closed',
			slug: `closed-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: closed._id,
			clientIds: ['verify-closed-app']
		});

		const auth = new AuthorizationRequest({
			client_id: 'verify-closed-app',
			scope: 'openid'
		});
		const started = await agent.auth.get({ query: auth.params });
		const uid = getHeader(started.response, 'location').split('/')[2];
		const cookie = present(
			started.response.headers.get('set-cookie'),
			"started.response.headers.get('set-cookie')"
		);
		const email = 'closed-user@x.io';
		const res = await agent
			.ui({ uid })
			.registration.post(
				{ email, password: PASSWORD, confirmPassword: PASSWORD },
				{ headers: { cookie } }
			);
		expect(res.response.status).toBe(403);
		expect(await getUserStore(closed._id).findByEmail(email)).toBeNull();
		expect(sentEmails.length).toBe(0);
	});

	it('creates a verified account with no email when verification is off', async () => {
		const off = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'No Verify Bucket',
			emailVerificationRequired: false
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Off',
			slug: `off-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: off._id,
			clientIds: ['verify-off-app']
		});

		const auth = new AuthorizationRequest({
			client_id: 'verify-off-app',
			scope: 'openid'
		});
		const started = await agent.auth.get({ query: auth.params });
		const uid = getHeader(started.response, 'location').split('/')[2];
		const cookie = present(
			started.response.headers.get('set-cookie'),
			"started.response.headers.get('set-cookie')"
		);
		const email = 'off-user@x.io';
		const res = await agent
			.ui({ uid })
			.registration.post(
				{ email, password: PASSWORD, confirmPassword: PASSWORD },
				{ headers: { cookie } }
			);
		expect(res.response.status).toBe(303);
		const user = await getUserStore(off._id).findByEmail(email);
		expect(user?.verified).toBe(true);
		expect(sentEmails.length).toBe(0);

		// verified immediately → login succeeds
		const auth2 = new AuthorizationRequest({
			client_id: 'verify-off-app',
			scope: 'openid'
		});
		const s2 = await agent.auth.get({ query: auth2.params });
		const uid2 = getHeader(s2.response, 'location').split('/')[2];
		const cookie2 = present(
			s2.response.headers.get('set-cookie'),
			"s2.response.headers.get('set-cookie')"
		);
		const login = await agent
			.ui({ uid: uid2 })
			.login.post(
				{ username: email, password: PASSWORD },
				{ headers: { cookie: cookie2 } }
			);
		expect(login.response.status).toBe(303);
	});
});
