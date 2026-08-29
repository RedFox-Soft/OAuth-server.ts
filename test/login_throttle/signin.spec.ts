import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { elysia } from 'lib/index.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { eventBus } from 'lib/event_bus.ts';
import { throttleKey } from 'lib/login_throttle/throttle.ts';
import type { LoginThrottlePayload } from 'lib/login_throttle/types.ts';
import { TestAdapter } from 'test/models.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * The password door under brute force, driven through the real HTTP layer: /auth to get an
 * interaction, then POST /ui/:uid/login exactly as a browser would.
 *
 * The single most important assertion in this file is not that a wrong password is refused — the door
 * already did that — but that the CORRECT one is refused once the cap is reached, and that the refusal
 * is indistinguishable from the ordinary one. A throttle whose refusal looks different is an
 * account-existence oracle bolted onto a door built to be non-committal.
 */

const PASSWORD = 'correct horse battery';
const WRONG = 'not the password';

/* The one message every failed sign-in produces, whatever the reason. */
const INVALID_CREDENTIALS = 'Invalid username or password';

const CAP = ApplicationConfig['loginThrottle.failureCap'] as number;
const WINDOW = ApplicationConfig['loginThrottle.windowSeconds'] as number;
const CEILING = ApplicationConfig[
	'loginThrottle.windowCeilingSeconds'
] as number;

let passwordBucketId: string;
let secondFactorBucketId: string;

let seq = 0;
const unique = (prefix: string) => `${prefix}-${(seq += 1)}@x.io`;

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

async function seedUser(bucketId: string, email: string) {
	return getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
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

/*
 * One sign-in attempt, from a fresh interaction every time. Fresh deliberately: a counter that lived
 * on the interaction would be defeated by starting a new one, which costs an attacker one request, so
 * every case here pays that cost to prove the counter does not live there.
 */
async function attempt(clientId: string, email: string, password: string) {
	const { uid, cookie } = await startInteraction(clientId);
	const res = await postForm(`/ui/${uid}/login`, cookie, {
		username: email,
		password
	});
	return { ...res, uid };
}

/*
 * The rendered page with its interaction id blanked out.
 *
 * Two attempts always carry different uids — the page embeds it in the form action, the props and
 * every link — and that difference is a property of having started two interactions, not of the
 * address. Comparing raw bodies would fail on it and prove nothing; comparing them with the uid
 * removed is the actual claim: nothing else about the response differs between an address that
 * exists and one that does not.
 */
function withoutUid(res: { text: string; uid: string }): string {
	return res.text.replaceAll(res.uid, '<uid>');
}

async function exhaust(clientId: string, email: string) {
	for (let i = 0; i < CAP; i += 1) {
		const res = await attempt(clientId, email, WRONG);
		expect(res.text).toContain(INVALID_CREDENTIALS);
	}
}

function counter(
	bucketId: string,
	email: string
): LoginThrottlePayload | undefined {
	return TestAdapter.for('LoginThrottle').syncFind(
		throttleKey(bucketId, email)
	) as LoginThrottlePayload | undefined;
}

/* Reopen the door without waiting, leaving `step` where it is — the state a real lockout ends in. */
function reopen(bucketId: string, email: string, by = CEILING + 1) {
	const held = counter(bucketId, email);
	if (!held) throw new Error('expected a counter to reopen');
	TestAdapter.for('LoginThrottle').syncUpdate(throttleKey(bucketId, email), {
		windowStart: held.windowStart - by
	});
}

function expectSignedIn(res: { status: number; setCookie: string | null }) {
	expect(res.status).toBe(303);
	expect(res.setCookie ?? '').toContain('_session=');
}

describe('password door brute-force throttle', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'login_throttle' });
		resetAdminMemoryStores();
		passwordBucketId = await seedBucket(
			'Throttle password only',
			'throttle-password-app',
			{ totpRequired: false }
		);
		secondFactorBucketId = await seedBucket(
			'Throttle second factor',
			'throttle-second-factor-app',
			{ totpRequired: true }
		);
	});

	describe('an attacker guessing one password (US1)', () => {
		it('refuses the correct password once the cap is reached', async () => {
			const email = unique('locked');
			await seedUser(passwordBucketId, email);

			await exhaust('throttle-password-app', email);

			const res = await attempt('throttle-password-app', email, PASSWORD);
			expect(res.text).toContain(INVALID_CREDENTIALS);
			expect(res.setCookie ?? '').not.toContain('_session=');
		});

		it('lets the correct password through once the window has elapsed', async () => {
			const email = unique('reopens');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);
			reopen(passwordBucketId, email);

			expectSignedIn(await attempt('throttle-password-app', email, PASSWORD));
		});

		it('verifies no password while the door is shut', async () => {
			const email = unique('nohash');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);

			// The CPU-exhaustion half of the issue: a refused guess must not cost an argon2 verify.
			const verify = spyOn(Bun.password, 'verify');
			try {
				await attempt('throttle-password-app', email, PASSWORD);
				expect(verify).not.toHaveBeenCalled();
			} finally {
				verify.mockRestore();
			}
		});

		it('does not extend the current window when an attacker keeps knocking', async () => {
			const email = unique('knocking');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);
			const shut = counter(passwordBucketId, email);

			await attempt('throttle-password-app', email, WRONG);
			await attempt('throttle-password-app', email, WRONG);

			const after = counter(passwordBucketId, email);
			expect(after?.windowStart).toBe(shut?.windowStart);
			expect(after?.step).toBe(shut?.step);
		});

		it('shuts the door for longer the second time', async () => {
			const email = unique('escalates');
			await seedUser(passwordBucketId, email);

			await exhaust('throttle-password-app', email);
			expect(counter(passwordBucketId, email)?.step).toBe(0);

			reopen(passwordBucketId, email);
			await exhaust('throttle-password-app', email);

			expect(counter(passwordBucketId, email)?.step).toBe(1);
			// Still refused after the *first* window's length, which is what "longer" means from outside.
			reopen(passwordBucketId, email, WINDOW + 1);
			const res = await attempt('throttle-password-app', email, PASSWORD);
			expect(res.text).toContain(INVALID_CREDENTIALS);
		});

		it('forgets the escalation once the counter has aged out', async () => {
			const email = unique('decays');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);
			reopen(passwordBucketId, email);
			await exhaust('throttle-password-app', email);
			expect(counter(passwordBucketId, email)?.step).toBe(1);

			TestAdapter.for('LoginThrottle').syncUpdate(
				throttleKey(passwordBucketId, email),
				{ exp: epochTime() - 1 }
			);

			await attempt('throttle-password-app', email, WRONG);
			expect(counter(passwordBucketId, email)?.step).toBe(0);
		});

		it('announces the refusal without naming the address', async () => {
			const email = unique('announced');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);

			const seen: unknown[] = [];
			const faults: unknown[] = [];
			const onThrottled = (payload: unknown) => seen.push(payload);
			const onFault = (payload: unknown) => faults.push(payload);
			eventBus.on('login_throttled', onThrottled);
			eventBus.on('server_error', onFault);

			try {
				await attempt('throttle-password-app', email, PASSWORD);
			} finally {
				eventBus.off('login_throttled', onThrottled);
				eventBus.off('server_error', onFault);
			}

			expect(seen).toHaveLength(1);
			expect(seen[0]).toEqual({ bucketId: passwordBucketId });
			// A deliberate refusal reported as a fault is a fault an operator learns to ignore.
			expect(faults).toHaveLength(0);
		});

		it('says nothing about the throttle in the page it renders', async () => {
			const email = unique('quiet');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);

			const res = await attempt('throttle-password-app', email, PASSWORD);
			expect(res.text.toLowerCase()).not.toContain('too many');
			expect(res.text.toLowerCase()).not.toContain('locked');
			expect(res.text.toLowerCase()).not.toContain('attempt');
			expect(res.text.toLowerCase()).not.toContain('minute');
		});
	});

	describe('the honest user (US2)', () => {
		it('signs in immediately after mistyping fewer times than the cap', async () => {
			const email = unique('fatfinger');
			await seedUser(passwordBucketId, email);

			for (let i = 0; i < CAP - 1; i += 1) {
				await attempt('throttle-password-app', email, WRONG);
			}

			expectSignedIn(await attempt('throttle-password-app', email, PASSWORD));
		});

		it('starts counting from zero again after a successful sign-in', async () => {
			const email = unique('resets');
			await seedUser(passwordBucketId, email);

			for (let i = 0; i < CAP - 1; i += 1) {
				await attempt('throttle-password-app', email, WRONG);
			}
			await attempt('throttle-password-app', email, PASSWORD);
			expect(counter(passwordBucketId, email)).toBeUndefined();

			await attempt('throttle-password-app', email, WRONG);
			expect(counter(passwordBucketId, email)?.failures).toBe(1);
		});

		it('clears the counter for a verifying password the door then refuses anyway', async () => {
			const email = unique('inactive');
			const user = await seedUser(passwordBucketId, email);
			for (let i = 0; i < CAP - 1; i += 1) {
				await attempt('throttle-password-app', email, WRONG);
			}
			await getUserStore(passwordBucketId).update(user._id, { active: false });

			const res = await attempt('throttle-password-app', email, PASSWORD);

			// Refused, unchanged, and indistinguishable — but the credential was proved, so nothing counts.
			expect(res.text).toContain(INVALID_CREDENTIALS);
			expect(counter(passwordBucketId, email)).toBeUndefined();
		});

		it('holds a second-factor bucket at the first window however often it is tripped', async () => {
			const email = unique('twofactor');
			await seedUser(secondFactorBucketId, email);

			await exhaust('throttle-second-factor-app', email);
			reopen(secondFactorBucketId, email, WINDOW + 1);
			await exhaust('throttle-second-factor-app', email);
			expect(counter(secondFactorBucketId, email)?.step).toBeGreaterThan(0);

			/*
			 * One first-window length later the door is open again, where the password-only bucket at the
			 * same step would still be shut. This is FR-025 seen from outside, and it is the case that
			 * fails if the ceiling is decided by the bucket's identity instead of its policy.
			 */
			reopen(secondFactorBucketId, email, WINDOW + 1);
			const res = await attempt('throttle-second-factor-app', email, PASSWORD);
			expect(res.text).not.toContain(INVALID_CREDENTIALS);
		});
	});

	describe('what the throttle reveals (US3)', () => {
		it('answers a registered and an unregistered address identically at every step', async () => {
			const registered = unique('known');
			const unknown = unique('unknown');
			await seedUser(passwordBucketId, registered);

			for (let i = 0; i < CAP + 2; i += 1) {
				const a = await attempt('throttle-password-app', registered, WRONG);
				const b = await attempt('throttle-password-app', unknown, WRONG);
				expect(a.status).toBe(b.status);
				expect(withoutUid(a)).toBe(withoutUid(b));
			}
		});

		it('counts failures for an address that has no account', async () => {
			const email = unique('ghost');

			await exhaust('throttle-password-app', email);

			// A record here means somebody typed this address, not that it resolves to anyone.
			const held = counter(passwordBucketId, email);
			expect(held?.failures).toBe(CAP);
			expect(held).not.toHaveProperty('accountId');
		});

		it('gives no fresh allowance to a different casing of the same address', async () => {
			const email = unique('MiXeD');
			await seedUser(passwordBucketId, email);

			const spellings = [
				email.toLowerCase(),
				email.toUpperCase(),
				email,
				email.replace('@', '@').toLowerCase()
			];
			for (let i = 0; i < CAP; i += 1) {
				const res = await attempt(
					'throttle-password-app',
					spellings[i % spellings.length] as string,
					WRONG
				);
				expect(res.text).toContain(INVALID_CREDENTIALS);
			}

			/*
			 * A 16-letter address has 2^16 casings that all resolve to one account. If each got its own
			 * counter the throttle would be a decoration — and every test written in lower case would pass.
			 */
			const res = await attempt(
				'throttle-password-app',
				email.toUpperCase(),
				PASSWORD
			);
			expect(res.text).toContain(INVALID_CREDENTIALS);
		});
	});

	describe('scope of the counter (US4)', () => {
		it('keeps the same address in two buckets apart', async () => {
			const email = unique('twobuckets');
			await seedUser(passwordBucketId, email);
			await seedUser(secondFactorBucketId, email);

			await exhaust('throttle-password-app', email);

			expect(counter(secondFactorBucketId, email)).toBeUndefined();
			const res = await attempt('throttle-second-factor-app', email, PASSWORD);
			expect(res.text).not.toContain(INVALID_CREDENTIALS);
		});

		it('treats a counter past its retention as absent', async () => {
			const email = unique('stale');
			await seedUser(passwordBucketId, email);
			await exhaust('throttle-password-app', email);

			TestAdapter.for('LoginThrottle').syncUpdate(
				throttleKey(passwordBucketId, email),
				{ exp: epochTime() - 1 }
			);

			// Still stored — MongoDB's TTL monitor reaps lazily — but it must not still refuse.
			expect(counter(passwordBucketId, email)).toBeDefined();
			expectSignedIn(await attempt('throttle-password-app', email, PASSWORD));
		});
	});
});
