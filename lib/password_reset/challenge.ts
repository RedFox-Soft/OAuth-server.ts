import crypto from 'crypto';

import { adapter, getUserStore, getBucketStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { ISSUER } from '../configs/env.js';
import { endSessionsForAccount } from '../helpers/cascade.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import epochTime from '../helpers/epoch_time.js';
import { clearFailures } from '../login_throttle/throttle.js';
import {
	nextRateFields,
	rateRefusal,
	type RateBounds
} from '../helpers/rate_window.js';
import { sendPasswordResetEmail } from '../mail/send.js';
import {
	RESET_TTL_SECONDS,
	REQUEST_COOLDOWN_SECONDS,
	REQUEST_DAILY_CAP,
	REQUEST_WINDOW_SECONDS
} from './consts.js';
import type { PasswordResetChallengePayload } from './types.js';

function challenges() {
	return adapter('PasswordResetChallenge');
}

function throttles() {
	return adapter('PasswordResetThrottle');
}

/* Every email-scoped record shares this shape so one computed id serves the deletion cascade (D9). */
export function throttleKey(bucketId: string, email: string): string {
	return emailScopedId(bucketId, email);
}

// This flow's bounds for the shared window arithmetic. Separate counters from the verification resend, so
// exhausting one allowance cannot lock a user out of the other.
const REQUEST_BOUNDS: RateBounds = {
	cooldownSeconds: REQUEST_COOLDOWN_SECONDS,
	cap: REQUEST_DAILY_CAP,
	windowSeconds: REQUEST_WINDOW_SECONDS
};

function newToken(): string {
	return crypto.randomBytes(32).toString('base64url');
}

/*
 * The record's id. Unsalted SHA-256 is right here and would be wrong for a password: the input is 256 bits
 * of uniform randomness, so there is nothing to brute-force and nothing to rainbow-table — and a salted
 * digest could not be derived from the token alone, which is what keeps the lookup a point read.
 */
function challengeId(token: string): string {
	return crypto.createHash('sha256').update(token).digest('hex');
}

export function resetUrlFor(token: string): string {
	return `${ISSUER}/reset-password?token=${encodeURIComponent(token)}`;
}

export type RequestOutcome =
	{ ok: true; sent: boolean } | { ok: false; reason: 'cooldown' | 'daily' };

/*
 * Issue a fresh secret for the account and deliver it. The plaintext token exists only as a local and
 * inside the outgoing message: it is never returned, never logged, and never written.
 */
async function issueAndSend(
	user: Pick<User, '_id' | 'email'>,
	bucket: Pick<UserBucket, '_id' | 'name'>
): Promise<void> {
	const token = newToken();
	const id = challengeId(token);
	const now = epochTime();
	const key = throttleKey(bucket._id, user.email);

	/*
	 * Supersede the account's outstanding secret before writing the new one, so a user never holds two live
	 * ones. The pointer lives on the throttle record because that record outlives any single challenge —
	 * the challenge itself cannot be found by account without a scan.
	 */
	const prior = await throttles().find(key);
	if (prior?.challengeId) {
		await challenges().destroy(prior.challengeId);
	}

	await challenges().upsert(
		id,
		{
			accountId: user._id,
			bucketId: bucket._id,
			email: user.email.toLowerCase(),
			exp: now + RESET_TTL_SECONDS
		},
		RESET_TTL_SECONDS
	);

	// Every issue counts against the window: unlike verification, whose initial registration send is free,
	// there is no "initial" reset.
	await throttles().upsert(
		key,
		{
			...nextRateFields(prior, now, REQUEST_BOUNDS, true),
			challengeId: id,
			exp: now + REQUEST_WINDOW_SECONDS
		},
		REQUEST_WINDOW_SECONDS
	);

	const appName = bucket.name || 'the application';
	await sendPasswordResetEmail({
		email: user.email,
		appName,
		resetUrl: resetUrlFor(token)
	});
}

/*
 * Handle a reset request for an address in one bucket.
 *
 * `sent` is for tests and logs only — the route renders the same page either way, because a response that
 * varied with the outcome would answer "does this address have an account here?" for anyone who asked.
 */
export async function request(
	email: string,
	bucketId: string
): Promise<RequestOutcome> {
	/*
	 * The reserved admin bucket is not self-service. An end-user reset records no actor by design, and an
	 * operator's credentials must not be changeable through a path with nothing to attribute — the
	 * constitution puts every administrative change in the audit trail, so console passwords stay inside the
	 * admin plane's audited route. `resolveBucketForClient` maps the reserved console client straight here,
	 * so without this the console's own sign-in page would have offered exactly that path.
	 */
	if (bucketId === ADMIN_BUCKET_ID) {
		return { ok: true, sent: false };
	}

	const user = await getUserStore(bucketId).findByEmail(email);
	if (!user || !user.active) {
		return { ok: true, sent: false };
	}

	const bucket = await getBucketStore().find(bucketId);
	if (!bucket) {
		return { ok: true, sent: false };
	}

	const refusal = rateRefusal(
		await throttles().find(throttleKey(bucketId, user.email)),
		epochTime(),
		REQUEST_BOUNDS
	);
	if (refusal) {
		return { ok: false, reason: refusal };
	}

	try {
		await issueAndSend(user, bucket);
	} catch (err) {
		/*
		 * A send only happens for an address that *does* have an account here, so surfacing the failure would
		 * answer the question the uniform response exists to refuse. Logged for the operator, invisible to the
		 * requester; the secret stays valid, so a retry after the cooldown costs nothing.
		 */
		console.error('password reset email could not be delivered:', err);
		return { ok: true, sent: false };
	}

	return { ok: true, sent: true };
}

export type LoadOutcome =
	| { ok: true; id: string; challenge: PasswordResetChallengePayload }
	| { ok: false };

/*
 * Resolve a token to its challenge without consuming it, so retrieving the reset page cannot burn the
 * secret — mail clients and security scanners fetch links found in email.
 *
 * Every refusal is the same refusal: distinguishing "never existed" from "no longer valid" would tell the
 * holder of one dead token something about another.
 */
export async function load(token: string): Promise<LoadOutcome> {
	const id = challengeId(token);
	const challenge = await challenges().find(id);
	if (!challenge) {
		return { ok: false };
	}

	/*
	 * Expiry is compared here rather than left to the store. MongoDB's TTL monitor deletes lazily — a
	 * record can outlive its `expiresAt` by a minute or more under load — and for a secret that changes a
	 * credential, that is a minute of extra validity nobody asked for.
	 */
	if (challenge.exp <= epochTime()) {
		return { ok: false };
	}

	const bucket = await getBucketStore().find(challenge.bucketId);
	if (!bucket) {
		return { ok: false };
	}

	const user = await getUserStore(challenge.bucketId).find(challenge.accountId);
	if (!user || !user.active) {
		return { ok: false };
	}

	return { ok: true, id, challenge };
}

export type ConsumeOutcome =
	| { ok: true; failedAreas: readonly string[] }
	| { ok: false; reason: 'invalid' };

/*
 * Spend the secret and replace the password.
 *
 * Order is the contract. The challenge is destroyed *before* the account is updated, so a replay arriving
 * mid-flight finds nothing rather than racing the confirmation.
 *
 * `verified` is set alongside the password: receiving the secret proves control of the address on file,
 * which is exactly what the verification challenge proves. Without it an unverified account is a dead end —
 * sign-in is gated on `verified`, and re-registering is deliberately non-committal about an address that
 * already exists, so nothing would resend anything.
 *
 * The caller checks that the two password entries match. Keeping that out of here is what makes "a
 * mismatch does not consume the secret" true by construction rather than by discipline.
 */
export async function consume(
	token: string,
	password: string
): Promise<ConsumeOutcome> {
	const loaded = await load(token);
	if (!loaded.ok) {
		return { ok: false, reason: 'invalid' };
	}

	const { id, challenge } = loaded;
	await challenges().destroy(id);
	await throttles().destroy(throttleKey(challenge.bucketId, challenge.email));

	await getUserStore(challenge.bucketId).update(challenge.accountId, {
		password: await Bun.password.hash(password),
		verified: true
	});

	/*
	 * The sign-in door's failure counter goes too, and this is the whole of why the login throttle needs
	 * no email step of its own. Escalating lockouts are only safe while the honest user holds a route back
	 * that an attacker guessing passwords does not, and consuming this secret is exactly that route: it
	 * proves control of the address on file. A user who cannot wait out an hour-long lockout resets
	 * instead and is signing in immediately.
	 *
	 * Here rather than at the *request*, and the distinction is load-bearing: asking for a reset proves
	 * nothing, so clearing there would hand anyone who knows an address a way to wipe the counter that is
	 * holding them off. Placed after the update for the same reason the sweep below is — nothing is
	 * released for a password change that did not land.
	 */
	await clearFailures(challenge.bucketId, challenge.email);

	/*
	 * After the update, never before: a session must not be destroyed for a password change that then failed
	 * to land. A failed sweep is reported rather than thrown — the password *did* change, and telling the
	 * user otherwise is the one lie this flow cannot afford.
	 */
	const swept = await endSessionsForAccount(challenge.accountId);
	if (swept.failedAreas.length > 0) {
		console.error(
			`password reset for account ${challenge.accountId}: password changed, but sessions survive in: ${swept.failedAreas.join(', ')}`
		);
	}

	return { ok: true, failedAreas: swept.failedAreas };
}
