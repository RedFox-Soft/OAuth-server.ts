import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import crypto from 'node:crypto';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	adapter,
	getUserStore,
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { TestAdapter } from '../models.ts';
import { Session } from 'lib/models/session.js';
import {
	sentEmails,
	resetSentEmails,
	lastEmail,
	extractResetUrl
} from '../mail_capture.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from 'lib/admin/consts.ts';
import { REQUEST_COOLDOWN_SECONDS } from 'lib/password_reset/consts.ts';
import { elysia } from 'lib/index.ts';

const CLIENT_ID = 'reset-app';
const OTHER_CLIENT_ID = 'reset-other-app';
const OLD_PASSWORD = 'correct horse battery';
const NEW_PASSWORD = 'staple correct horse';

let bucketId: string;
// A second bucket, reached by a second client and requiring verification — so "an address registered
// elsewhere is not found here" is a real routing outcome, and the unverified-account case has somewhere to
// live where sign-in is actually gated on `verified`.
let otherBucketId: string;

// Drive a real authorization request so the provider prompts login and hands back an interaction uid and
// its `_interaction` cookie — the reset request form lives inside that interaction, because the bucket an
// address is looked up in has to come from the client that started the request.
async function startInteraction(clientId = CLIENT_ID) {
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

async function seedUser(email: string, area = bucketId) {
	return getUserStore(area).create(
		email,
		await Bun.password.hash(OLD_PASSWORD),
		[],
		true
	);
}

async function requestReset(email: string, clientId = CLIENT_ID) {
	const { uid, cookie } = await startInteraction(clientId);
	const result = await agent
		.ui({ uid })
		['forgot-password'].post({ email }, { headers: { cookie } });
	// `data` travels with the result so callers can compare rendered pages, not just statuses.
	return { uid, cookie, response: result.response, data: result.data };
}

// The token as the user receives it: read out of the captured mail, never out of storage — storage holds
// only its digest.
function tokenFromMail(): string {
	const email = lastEmail();
	if (!email) throw new Error('expected a reset email');
	const url = extractResetUrl(email);
	if (!url) throw new Error('expected a reset link in the email body');
	const token = new URL(url).searchParams.get('token');
	if (!token) throw new Error('expected a token on the reset link');
	return token;
}

/*
 * The Eden client has already read the body by the time it hands back a response, so `response.text()`
 * throws ERR_BODY_ALREADY_USED. A 2xx body lands in `data`; a 4xx/5xx body lands in `error.value`. Both are
 * documents here, and comparing rendered pages (not just statuses) is what pins "indistinguishable".
 */
function bodyOf(result: { data?: unknown; error?: unknown }): string {
	if (typeof result.data === 'string') return result.data;
	const value = (result.error as { value?: unknown } | null | undefined)?.value;
	return typeof value === 'string' ? value : String(result.data ?? value);
}

/*
 * Post the request form through the app directly. Needed only where a *refusal* page's text matters: the
 * Eden client hands back no readable body for some non-2xx HTML responses, and elysia.handle returns the
 * real Response.
 */
async function postRequestForm(
	uid: string,
	cookie: string,
	email: string
): Promise<{ status: number; text: string }> {
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/forgot-password`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams({ email }).toString()
		})
	);
	return { status: res.status, text: await res.text() };
}

// Clear the per-address cooldown without touching the cap, for tests about something other than the clock.
function clearCooldown(email: string, area = bucketId): void {
	TestAdapter.for('PasswordResetThrottle').syncUpdate(`${area}:${email}`, {
		lastSentAt: epochTime() - REQUEST_COOLDOWN_SECONDS - 1
	});
}

async function login(
	uid: string,
	cookie: string,
	email: string,
	password: string
) {
	const { response } = await agent
		.ui({ uid })
		.login.post({ username: email, password }, { headers: { cookie } });
	return response.status;
}

// What the server stores for a token. Computed here rather than imported so the test asserts the *scheme*
// (the record is addressed by a digest, so storage cannot reproduce the secret) instead of agreeing with
// whatever the implementation happens to do.
function digestOf(token: string): string {
	return crypto.createHash('sha256').update(token).digest('hex');
}

// Age a live secret past its window while leaving it in storage — a record MongoDB's TTL monitor has not
// got round to yet. The house helper for this is TestAdapter.syncUpdate (see authorization_code specs).
function expire(token: string): void {
	TestAdapter.for('PasswordResetChallenge').syncUpdate(digestOf(token), {
		exp: epochTime() - 1
	});
}

// File-level, so every describe below shares one bootstrap and one bucket. Each describe still resets the
// mail capture in its own `beforeEach`: a top-level one does not apply to tests nested in a describe.
beforeAll(async () => {
	await bootstrap(import.meta.url, { config: 'reset' });
	resetAdminMemoryStores();
	// A dedicated bucket reached by CLIENT_ID through a project, so these specs never touch the shared
	// 'redfox' bucket that the second client falls through to.
	const bucket = await getBucketStore().create({ name: 'Reset Bucket' });
	bucketId = bucket._id;
	const project = await getProjectStore().create({
		name: 'Reset',
		slug: `reset-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId,
		clientIds: [CLIENT_ID]
	});

	const other = await getBucketStore().create({
		name: 'Reset Other Bucket',
		emailVerificationRequired: true
	});
	otherBucketId = other._id;
	const otherProject = await getProjectStore().create({
		name: 'Reset Other',
		slug: `reset-other-${Math.random()}`
	});
	await getProjectStore().update(otherProject._id, {
		bucketId: otherBucketId,
		clientIds: [OTHER_CLIENT_ID]
	});
});

describe('password reset — the journey (US1)', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('emails a reset link for a registered address (scenario 1)', async () => {
		const email = 'journey-one@x.io';
		await seedUser(email);

		const { response } = await requestReset(email);

		expect(response.status).toBe(200);
		expect(sentEmails.length).toBe(1);
		expect(sentEmails[0]?.to).toBe(email);
		expect(extractResetUrl(sentEmails[0]!)).toContain('/reset-password?token=');
	});

	it('renders a form from the emailed link (scenario 2)', async () => {
		const email = 'journey-two@x.io';
		await seedUser(email);
		await requestReset(email);

		const res = await agent['reset-password'].get({
			query: { token: tokenFromMail() }
		});

		expect(res.response.status).toBe(200);
		const body = bodyOf(res);
		expect(body).toContain('name="password"');
		expect(body).toContain('name="confirmPassword"');
		// Nothing about the account beyond what the user typed a moment ago.
		expect(body).not.toContain(email);
	});

	it('replaces the password and refuses the old one (scenarios 3 and 4)', async () => {
		const email = 'journey-three@x.io';
		await seedUser(email);
		await requestReset(email);
		const token = tokenFromMail();

		const res = await agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});
		expect(res.response.status).toBe(200);

		const stale = await startInteraction();
		expect(await login(stale.uid, stale.cookie, email, OLD_PASSWORD)).toBe(400);

		const fresh = await startInteraction();
		expect(await login(fresh.uid, fresh.cookie, email, NEW_PASSWORD)).toBe(303);
	});

	it('leaves the secret usable when the two entries do not match (scenario 5)', async () => {
		const email = 'journey-four@x.io';
		const user = await seedUser(email);
		await requestReset(email);
		const token = tokenFromMail();

		const mismatch = await agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: 'something else'
		});
		expect(mismatch.response.status).toBe(400);
		const before = await getUserStore(bucketId).find(user._id);
		expect(
			await Bun.password.verify(OLD_PASSWORD, before?.password ?? '')
		).toBeTrue();

		// The same token still works, which is the point of not consuming on a mismatch.
		const retry = await agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});
		expect(retry.response.status).toBe(200);
		const after = await getUserStore(bucketId).find(user._id);
		expect(
			await Bun.password.verify(NEW_PASSWORD, after?.password ?? '')
		).toBeTrue();
	});

	it('reaches the request form from the login page', async () => {
		const { uid, cookie } = await startInteraction();

		const loginPage = await agent
			.ui({ uid })
			.login.get({ headers: { cookie } });
		expect(bodyOf(loginPage)).toContain(`/ui/${uid}/forgot-password`);

		const form = await agent
			.ui({ uid })
			['forgot-password'].get({ headers: { cookie } });
		expect(form.response.status).toBe(200);
		expect(bodyOf(form)).toContain('name="email"');
	});
});

describe('password reset — the secret (US2)', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	async function liveToken(email: string) {
		await seedUser(email);
		await requestReset(email);
		return tokenFromMail();
	}

	async function submit(token: string, password = NEW_PASSWORD) {
		return agent['reset-password'].post({
			token,
			password,
			confirmPassword: password
		});
	}

	it('refuses a secret that has already been used (scenario 1)', async () => {
		const email = 'secret-reuse@x.io';
		const token = await liveToken(email);
		expect((await submit(token)).response.status).toBe(200);

		const replay = await submit(token, 'third password entirely');

		expect(replay.response.status).toBe(400);
		const user = await getUserStore(bucketId).findByEmail(email);
		expect(
			await Bun.password.verify(NEW_PASSWORD, user?.password ?? '')
		).toBeTrue();
	});

	/*
	 * A record still in storage whose `exp` has passed — exactly the state MongoDB's lazy TTL monitor leaves
	 * behind, and the reason expiry is compared in the code path rather than delegated to the store.
	 *
	 * Aged with syncUpdate rather than written expired: the TestAdapter asserts that a written `exp` matches
	 * the TTL it was given, so an inconsistent record cannot be forged through upsert — which is the harness
	 * working as intended.
	 */
	it('refuses a secret whose window has passed (scenario 2)', async () => {
		const email = 'secret-expired@x.io';
		const user = await seedUser(email);
		await requestReset(email);
		const token = tokenFromMail();
		expire(token);

		const get = await agent['reset-password'].get({ query: { token } });
		expect(get.response.status).toBe(400);

		const post = await submit(token);
		expect(post.response.status).toBe(400);
		const after = await getUserStore(bucketId).find(user._id);
		expect(
			await Bun.password.verify(OLD_PASSWORD, after?.password ?? '')
		).toBeTrue();
	});

	it('kills the earlier secret when another is requested (scenario 3)', async () => {
		const email = 'secret-superseded@x.io';
		const first = await liveToken(email);
		// Supersession is about holding two secrets, not about how fast they were asked for.
		clearCooldown(email);
		await requestReset(email);
		const second = tokenFromMail();
		expect(second).not.toBe(first);

		expect((await submit(first)).response.status).toBe(400);
		expect((await submit(second)).response.status).toBe(200);
	});

	it('stores nothing that can be replayed as the secret (scenario 4)', async () => {
		const token = await liveToken('secret-at-rest@x.io');

		expect(await adapter('PasswordResetChallenge').find(token)).toBeUndefined();
		const stored = await adapter('PasswordResetChallenge').find(
			digestOf(token)
		);
		expect(stored).toBeDefined();
		expect(JSON.stringify(stored)).not.toContain(token);
	});

	it('answers an unknown secret exactly as it answers an expired one (scenario 5)', async () => {
		const email = 'secret-unknown@x.io';
		await seedUser(email);
		await requestReset(email);
		const expired = tokenFromMail();
		expire(expired);

		const unknown = await agent['reset-password'].get({
			query: { token: 'no-such-token-was-ever-issued' }
		});
		const stale = await agent['reset-password'].get({
			query: { token: expired }
		});

		expect(unknown.response.status).toBe(stale.response.status);
		expect(bodyOf(unknown)).toBe(bodyOf(stale));
	});

	it('refuses a secret whose account is gone or deactivated (scenario 6)', async () => {
		const deletedEmail = 'secret-deleted@x.io';
		const deleted = await seedUser(deletedEmail);
		await requestReset(deletedEmail);
		const orphaned = tokenFromMail();
		await getUserStore(bucketId).destroy(deleted._id);

		expect((await submit(orphaned)).response.status).toBe(400);

		const frozenEmail = 'secret-deactivated@x.io';
		const frozen = await seedUser(frozenEmail);
		await requestReset(frozenEmail);
		const frozenToken = tokenFromMail();
		await getUserStore(bucketId).update(frozen._id, { active: false });

		expect((await submit(frozenToken)).response.status).toBe(400);
	});

	it('survives a link a mail client fetched for the user (scenario 7)', async () => {
		const token = await liveToken('secret-prefetched@x.io');

		const first = await agent['reset-password'].get({ query: { token } });
		const second = await agent['reset-password'].get({ query: { token } });
		expect(first.response.status).toBe(200);
		expect(second.response.status).toBe(200);

		expect((await submit(token)).response.status).toBe(200);
	});
});

describe('password reset — sessions (US3)', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	async function resetFor(email: string) {
		await requestReset(email);
		const token = tokenFromMail();
		return agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});
	}

	// `save()` is typed `string | undefined`, so the id is narrowed once here rather than at four call sites.
	async function signIn(accountId: string) {
		const session = new Session({ accountId, loginTs: epochTime() });
		const id = await session.save();
		if (!id) throw new Error('expected a saved session to have an id');
		return { id, uid: session.payload.uid };
	}

	it('destroys the account sessions (scenario 1)', async () => {
		const email = 'session-mine@x.io';
		const user = await seedUser(email);
		const session = await signIn(user._id);
		expect(await adapter('Session').find(session.id)).toBeDefined();

		const res = await resetFor(email);
		expect(res.response.status).toBe(200);

		expect(await adapter('Session').find(session.id)).toBeUndefined();
		expect(await adapter('Session').findByUid(session.uid)).toBeUndefined();
	});

	it('leaves another user signed in (scenario 2)', async () => {
		const mineEmail = 'session-two-mine@x.io';
		const mine = await seedUser(mineEmail);
		const theirs = await seedUser('session-two-theirs@x.io');
		const mySession = await signIn(mine._id);
		const theirSession = await signIn(theirs._id);

		await resetFor(mineEmail);

		expect(await adapter('Session').find(mySession.id)).toBeUndefined();
		expect(await adapter('Session').find(theirSession.id)).toBeDefined();
	});

	/*
	 * The password changed; saying otherwise would be the one lie this flow cannot afford. The sweep failure
	 * is reported through the outcome (and logged) while the user is still told the truth.
	 *
	 * The spy goes in this test rather than a beforeAll: bun's mock.restore() in an afterEach clears spies
	 * installed there, unlike sinon.
	 */
	it('still reports success when the sweep fails (scenario 3)', async () => {
		const email = 'session-sweep-fails@x.io';
		const user = await seedUser(email);
		const sessions = adapter('Session');
		const sweep = spyOn(sessions, 'destroyByOwner').mockRejectedValue(
			new Error('storage is having a day')
		);

		const res = await resetFor(email);

		expect(sweep).toHaveBeenCalled();
		expect(res.response.status).toBe(200);
		const after = await getUserStore(bucketId).find(user._id);
		expect(
			await Bun.password.verify(NEW_PASSWORD, after?.password ?? '')
		).toBeTrue();
		sweep.mockRestore();
	});
});

describe('password reset — not a prober, not a mailer (US4)', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	// The accepted page is a constant, so this is the assertion that pins it: five different outcomes, one
	// response. Compared as bodies, not statuses — a status alone would not catch a helpful hint in the text.
	it('answers registered and unresolvable addresses identically (scenarios 1, 2, 3)', async () => {
		const registered = 'prober-registered@x.io';
		await seedUser(registered);
		const elsewhere = 'prober-elsewhere@x.io';
		await seedUser(elsewhere, otherBucketId);
		const deactivated = 'prober-deactivated@x.io';
		const frozen = await seedUser(deactivated);
		await getUserStore(bucketId).update(frozen._id, { active: false });
		const operator = 'prober-operator@x.io';
		await seedUser(operator, ADMIN_BUCKET_ID);

		const accepted = await requestReset(registered);
		expect(sentEmails.length).toBe(1);

		const unknown = await requestReset('nobody-here@x.io');
		const crossBucket = await requestReset(elsewhere);
		const inactive = await requestReset(deactivated);
		const adminBucket = await requestReset(operator, ADMIN_CLIENT_ID);

		for (const other of [unknown, crossBucket, inactive, adminBucket]) {
			expect(other.response.status).toBe(accepted.response.status);
			expect(bodyOf(other)).toBe(bodyOf(accepted));
		}
		// Exactly one message, for the one address that resolved to a live account in this bucket.
		expect(sentEmails.length).toBe(1);
		expect(sentEmails[0]?.to).toBe(registered);
	});

	it('refuses a second request inside the cooldown (scenario 4)', async () => {
		const email = 'mailer-cooldown@x.io';
		await seedUser(email);

		const first = await requestReset(email);
		expect(first.response.status).toBe(200);
		const second = await requestReset(email);

		expect(second.response.status).toBe(429);
		expect(sentEmails.length).toBe(1);
	});

	/*
	 * Past the cooldown but at the cap. The window is aged rather than filled by five real requests: the
	 * cooldown would refuse those, and what is under test here is the cap, not the clock.
	 */
	it('refuses a request past the daily cap, and says something different (scenario 5)', async () => {
		const email = 'mailer-cap@x.io';
		await seedUser(email);
		await requestReset(email);
		const now = epochTime();
		TestAdapter.for('PasswordResetThrottle').syncUpdate(
			`${bucketId}:${email}`,
			{
				lastSentAt: now - 61,
				dayCount: 5,
				windowStart: now
			}
		);
		resetSentEmails();

		const start = await startInteraction();
		const capped = await postRequestForm(start.uid, start.cookie, email);

		expect(capped.status).toBe(429);
		expect(sentEmails.length).toBe(0);

		// The two refusals are distinguishable, so a user knows whether to wait a minute or a day.
		const cooldownEmail = 'mailer-cap-other@x.io';
		await seedUser(cooldownEmail);
		await requestReset(cooldownEmail);
		const cooldownStart = await startInteraction();
		const cooled = await postRequestForm(
			cooldownStart.uid,
			cooldownStart.cookie,
			cooldownEmail
		);
		expect(cooled.status).toBe(429);
		expect(capped.text).not.toBe(cooled.text);
	});

	/*
	 * A transport that fails must not become an existence oracle: the send only happens for an address that
	 * *does* have an account, so surfacing the failure would answer the question the uniform page exists to
	 * refuse. Forced at the mailer's own boundary — under NODE_ENV=test `deliver` records into this array.
	 */
	it('hides a delivery failure behind the accepted page (scenario 6)', async () => {
		const email = 'mailer-broken@x.io';
		await seedUser(email);
		const push = spyOn(sentEmails, 'push').mockImplementation(() => {
			throw new Error('smtp refused the message');
		});

		try {
			const res = await requestReset(email);
			expect(res.response.status).toBe(200);
		} finally {
			// Restored in a finally: a leaked push spy makes every later test in the file fail for the wrong
			// reason, which is exactly what happened the first time this was written.
			push.mockRestore();
		}
		expect(sentEmails.length).toBe(0);
	});

	// Receiving the secret proves control of the address, which is what the verification challenge proves.
	// Without this an unverified account is a dead end: it cannot sign in and cannot re-register.
	it('verifies the address it just proved, and lets the user in', async () => {
		const email = 'unverified-user@x.io';
		const user = await getUserStore(otherBucketId).create(
			email,
			await Bun.password.hash(OLD_PASSWORD),
			[],
			false
		);
		expect(user.verified).toBeFalse();

		await requestReset(email, OTHER_CLIENT_ID);
		const token = tokenFromMail();
		const res = await agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});
		expect(res.response.status).toBe(200);

		const after = await getUserStore(otherBucketId).find(user._id);
		expect(after?.verified).toBeTrue();

		const { uid, cookie } = await startInteraction(OTHER_CLIENT_ID);
		expect(await login(uid, cookie, email, NEW_PASSWORD)).toBe(303);
	});

	// No operator acted, so the trail records nothing. The constitution's immutable audit log must not be
	// writable by an anonymous request.
	it('writes nothing to the admin audit trail', async () => {
		const before = (await adminAuditStore.list({})).total;
		const email = 'audit-silent@x.io';
		await seedUser(email);

		await requestReset(email);
		await agent['reset-password'].post({
			token: tokenFromMail(),
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});

		expect((await adminAuditStore.list({})).total).toBe(before);
	});
});
