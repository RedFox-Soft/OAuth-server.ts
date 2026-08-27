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
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { Session } from 'lib/models/session.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import {
	ACCOUNT_FAILURE_CAP,
	MAX_ATTEMPTS_PER_INTERACTION
} from 'lib/totp/consts.ts';
import epochTime from 'lib/helpers/epoch_time.ts';

const PASSWORD = 'correct horse battery';
const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));

// The one message every failed code produces, whatever the reason.
const INVALID_CODE = 'Invalid code';
const INVALID_CREDENTIALS = 'Invalid username or password';

let requiredBucketId: string;
let optionalBucketId: string;

/*
 * What an authenticator app would be showing right now. Uses the same primitives the server does —
 * they are proved against the RFC vectors in algorithm.spec.ts, so a bug in them fails there rather
 * than making every test in this file agree with the server about something wrong.
 */
function currentCode(at = epochTime()): string {
	return hotp(decodeBase32(SECRET), stepFor(at));
}

async function seedBucket(
	name: string,
	clientId: string,
	fields: Record<string, unknown>
): Promise<string> {
	const bucket = await getBucketStore().create({ name, ...fields });
	const project = await getProjectStore().create({
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
		csp: res.headers.get('content-security-policy'),
		contentType: res.headers.get('content-type') ?? ''
	};
}

/*
 * The `amr` recorded on a session, read back through the model.
 *
 * Narrowed at this one call site rather than by widening the model layer, exactly as
 * lib/admin/auth/login.ts narrows `Session.tryFind` and for the same pre-existing reason: `BaseModel`'s
 * `this` constraint does not admit `Session`'s own constructor, and its payload type collapses to the
 * base shape on the way out.
 */
async function amrOf(sessionId: string): Promise<string[] | undefined> {
	const session = await (
		Session as unknown as {
			find(id: string): Promise<{ payload: { amr?: string[] } } | undefined>;
		}
	).find(sessionId);
	return session?.payload.amr;
}

/* An account that already holds an authenticator, without driving the enrolment flow to create one. */
async function seedEnrolled(bucketId: string, email: string) {
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
	await getUserStore(bucketId).update(user._id, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
	});
	return user;
}

/*
 * What "the sign-in completed" looks like from the outside: a session cookie was issued and the
 * interaction moved on to the next prompt. Asserted as consent-or-callback rather than pinned to the
 * callback, because a first sign-in still has consent to collect — the important part is that the
 * request left the authentication step at all.
 */
function expectSignedIn(res: {
	status: number;
	location: string | null;
	setCookie: string | null;
}) {
	expect(res.status).toBe(303);
	expect(res.setCookie ?? '').toContain('_session=');
	expect(res.location ?? '').toMatch(/\/consent$|\/callback/);
}

/* Password accepted, code not yet supplied. */
async function passwordStep(clientId: string, email: string) {
	const { uid, cookie } = await startInteraction(clientId);
	const res = await postForm(`/ui/${uid}/login`, cookie, {
		username: email,
		password: PASSWORD
	});
	return { uid, cookie, res };
}

describe('second factor at sign-in (US3)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		requiredBucketId = await seedBucket('TOTP Required', 'totp-required-app', {
			totpRequired: true
		});
		optionalBucketId = await seedBucket('TOTP Optional', 'totp-optional-app', {
			totpRequired: false
		});
	});

	it('does not sign the person in on a correct password alone', async () => {
		const email = `pwd-only-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { res } = await passwordStep('totp-required-app', email);

		// Sent onward to the code step, and nothing was established on the way.
		expect(res.status).toBe(303);
		expect(res.location).toContain('/totp');
		expect(res.setCookie ?? '').not.toContain('_session=');
	});

	it('leaves the authorization request unfinished until the code is supplied', async () => {
		const email = `unfinished-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, res } = await passwordStep('totp-required-app', email);

		// Not handed back to the client, and no session issued: the redirect stays inside the interaction.
		expect(res.location).toContain(`/ui/${uid}/totp`);
		expect(res.setCookie ?? '').not.toContain('_session=');
	});

	it('renders a code page carrying no account detail', async () => {
		const email = `codepage-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		const page = await getPage(`/ui/${uid}/totp`, cookie);
		expect(page.status).toBe(200);
		expect(page.contentType).toContain('text/html');
		expect(page.csp).toBeTruthy();
		// The email is not shown: the page adds nothing by naming it and may be read over a shoulder.
		expect(page.text).not.toContain(email);
	});

	it('completes the sign-in on a correct code', async () => {
		const email = `good-code-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		const res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: currentCode()
		});
		expectSignedIn(res);
	});

	it('refuses a wrong code without revealing the password was right', async () => {
		const email = `bad-code-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		const res = await postForm(`/ui/${uid}/totp`, cookie, { code: '000001' });
		expect(res.status).toBe(400);
		expect(res.text).toContain(INVALID_CODE);
		expect(res.text).not.toContain(INVALID_CREDENTIALS);
		expect(res.location).toBeNull();
	});

	it('refuses a code that was already spent, inside its own window', async () => {
		const email = `replay-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const code = currentCode();

		const first = await passwordStep('totp-required-app', email);
		const ok = await postForm(`/ui/${first.uid}/totp`, first.cookie, { code });
		expectSignedIn(ok);

		// A second sign-in, same 30-second window, same code.
		const second = await passwordStep('totp-required-app', email);
		const replay = await postForm(`/ui/${second.uid}/totp`, second.cookie, {
			code
		});
		expect(replay.status).toBe(400);
		expect(replay.text).toContain(INVALID_CODE);
	});

	it('accepts a code from the adjacent step, tolerating clock drift', async () => {
		const email = `drift-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		const previousStep = hotp(decodeBase32(SECRET), stepFor(epochTime()) - 1);
		const res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: previousStep
		});
		expectSignedIn(res);
	});

	it('throttles repeated wrong codes within one sign-in attempt', async () => {
		const email = `throttle-int-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		for (let i = 0; i < MAX_ATTEMPTS_PER_INTERACTION; i += 1) {
			await postForm(`/ui/${uid}/totp`, cookie, { code: '000001' });
		}

		// Even the right code is refused now, and the wording does not change.
		const res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: currentCode()
		});
		expect(res.status).toBe(400);
		expect(res.text).toContain(INVALID_CODE);
	});

	// The per-interaction counter alone is defeated by starting a new interaction, which costs one request.
	it('throttles per account across sign-in attempts', async () => {
		const email = `throttle-acct-${Math.random()}@x.io`;
		const user = await seedEnrolled(requiredBucketId, email);

		for (let i = 0; i < ACCOUNT_FAILURE_CAP; i += 1) {
			const attempt = await passwordStep('totp-required-app', email);
			await postForm(`/ui/${attempt.uid}/totp`, attempt.cookie, {
				code: '000001'
			});
		}

		const fresh = await passwordStep('totp-required-app', email);
		const res = await postForm(`/ui/${fresh.uid}/totp`, fresh.cookie, {
			code: currentCode()
		});
		expect(res.status).toBe(400);
		expect(res.text).toContain(INVALID_CODE);

		const record = await adapter('TotpAttempt').find(
			`${requiredBucketId}:${user._id}`
		);
		expect(record).toBeDefined();
	});

	it('sends someone with no half-finished sign-in back to the login page', async () => {
		const { uid, cookie } = await startInteraction('totp-required-app');
		const page = await getPage(`/ui/${uid}/totp`, cookie);
		expect(page.status).toBe(303);
		expect(page.location).toContain(`/ui/${uid}/login`);
	});

	it('refuses a code POST with no half-finished sign-in', async () => {
		const { uid, cookie } = await startInteraction('totp-required-app');
		const res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: currentCode()
		});
		expect(res.status).toBe(303);
		expect(res.location).toContain(`/ui/${uid}/login`);
	});

	it('refuses the code page without the interaction cookie', async () => {
		const email = `nocookie-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid } = await passwordStep('totp-required-app', email);

		const page = await getPage(`/ui/${uid}/totp`);
		expect(page.status).toBeGreaterThanOrEqual(400);
	});

	it('still refuses an inactive account, before the code step is reached', async () => {
		const email = `inactive-${Math.random()}@x.io`;
		const user = await seedEnrolled(requiredBucketId, email);
		await getUserStore(requiredBucketId).update(user._id, { active: false });

		const { res } = await passwordStep('totp-required-app', email);
		expect(res.status).toBe(400);
		expect(res.text).toContain(INVALID_CREDENTIALS);
	});

	it('still refuses a wrong password, with no hint that an enrolment exists', async () => {
		const email = `wrongpwd-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await startInteraction('totp-required-app');

		const res = await postForm(`/ui/${uid}/login`, cookie, {
			username: email,
			password: 'not the password'
		});
		expect(res.status).toBe(400);
		expect(res.text).toContain(INVALID_CREDENTIALS);
		expect(res.text).not.toContain(INVALID_CODE);
	});

	/*
	 * FR-023. The session is where `amr` is recorded, and lib/helpers/process_response_types.ts reads it
	 * from there onto the ID token — so asserting the session carries it is asserting the whole chain,
	 * without exchanging a code for tokens to read a claim this server already puts there for every
	 * other `amr` producer.
	 */
	it('records two factors on the resulting session', async () => {
		const email = `amr-${Math.random()}@x.io`;
		await seedEnrolled(requiredBucketId, email);
		const { uid, cookie } = await passwordStep('totp-required-app', email);

		const res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: currentCode()
		});
		expectSignedIn(res);

		const sessionId = /_session=([^;]+)/.exec(res.setCookie ?? '')?.[1];
		expect(sessionId).toBeTruthy();
		expect(await amrOf(sessionId as string)).toEqual(['pwd', 'otp']);
	});

	it('leaves amr absent on a password-only sign-in, changing nothing for it', async () => {
		const email = `amr-absent-${Math.random()}@x.io`;
		await getUserStore(optionalBucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);
		const { res } = await passwordStep('totp-optional-app', email);

		const sessionId = /_session=([^;]+)/.exec(res.setCookie ?? '')?.[1];
		expect(await amrOf(sessionId as string)).toBeUndefined();
	});

	describe('a bucket that does not require the second factor', () => {
		it('signs in on the password alone, exactly as before', async () => {
			const email = `optional-${Math.random()}@x.io`;
			await getUserStore(optionalBucketId).create(
				email,
				await Bun.password.hash(PASSWORD),
				[],
				true
			);
			const { res } = await passwordStep('totp-optional-app', email);
			expectSignedIn(res);
		});

		// FR-024: an enrolled account in a bucket that does not require it is not asked for a code.
		it('asks no code even of an account that happens to be enrolled', async () => {
			const email = `optional-enrolled-${Math.random()}@x.io`;
			await seedEnrolled(optionalBucketId, email);
			const { res } = await passwordStep('totp-optional-app', email);
			expectSignedIn(res);
		});
	});
});
