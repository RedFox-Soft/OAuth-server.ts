import crypto from 'crypto';

import {
	checkedAdapter,
	getUserStore,
	getBucketStore
} from '../adapters/index.js';
import {
	PasswordResetChallengePayload,
	PasswordResetThrottlePayload,
	type SetPasswordPurpose
} from './types.js';
import type { User, UserBucket } from '../adapters/types.js';
import { shownNameOf } from '../configs/issuer.js';
import { ISSUER } from '../configs/env.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { endSessionsForAccount } from '../helpers/cascade.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import epochTime from '../helpers/epoch_time.js';
import { clearFailures } from '../login_throttle/throttle.js';
import {
	nextRateFields,
	rateRefusal,
	type RateBounds
} from '../helpers/rate_window.js';
import { MailNotConfiguredError } from '../mail/mailer.js';
import {
	sendPasswordResetEmail,
	sendUserInvitationEmail
} from '../mail/send.js';
import { selfServiceResetAllowed } from './eligibility.js';
import { ReplayDetection } from '../models/replay_detection.js';
import {
	INVITE_TTL_SECONDS,
	RESET_TTL_SECONDS,
	REQUEST_COOLDOWN_SECONDS,
	REQUEST_DAILY_CAP,
	REQUEST_WINDOW_SECONDS
} from './consts.js';
import type { Language } from '../i18n/languages.js';
import { emailLanguage, type LocaleHolder } from '../i18n/resolve.js';

function challenges() {
	return checkedAdapter(
		'PasswordResetChallenge',
		PasswordResetChallengePayload
	);
}

function throttles() {
	return checkedAdapter('PasswordResetThrottle', PasswordResetThrottlePayload);
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

/* What one issue is for, how long its secret lives, and how its message goes out. */
interface IssuePlan {
	purpose: SetPasswordPurpose;
	ttl: number;
	/* The language of the page the person asked from, when they did (specs/097). */
	language?: Language;
	send: (
		to: string,
		bucketName: string,
		url: string,
		language: Language
	) => Promise<void>;
}

/*
 * Issue a fresh secret for the account and deliver it. The plaintext token exists only as a local and
 * inside the outgoing message: it is never returned, never logged, and never written.
 *
 * A reset and an invitation share this, and the one outstanding secret per person: whichever was issued last
 * is the only one that works, so an invitation supersedes a reset link and the reverse.
 */
async function issueAndSend(
	user: Pick<User, '_id' | 'email'> & LocaleHolder,
	bucket: Pick<UserBucket, '_id' | 'name'>,
	plan: IssuePlan
): Promise<void> {
	const language = emailLanguage(user, plan.language);
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
			exp: now + plan.ttl,
			purpose: plan.purpose,
			language
		},
		plan.ttl
	);

	/*
	 * The pointer that supersedes a link must live as long as that link. Bounded by the rate window alone, a
	 * seven-day invitation resent after a day found no pointer, and the first link stayed alive beside the
	 * second. `windowStart` still measures the cap, so a longer-lived record limits nothing more.
	 */
	const recordTtl = Math.max(REQUEST_WINDOW_SECONDS, plan.ttl);
	// Every issue counts against the window: unlike verification, whose initial registration send is free,
	// there is no "initial" reset.
	await throttles().upsert(
		key,
		{
			...nextRateFields(prior, now, REQUEST_BOUNDS, true),
			challengeId: id,
			exp: now + recordTtl
		},
		recordTtl
	);

	await plan.send(
		user.email,
		shownNameOf(bucket),
		resetUrlFor(token),
		language
	);
}

/*
 * The self-service reset's delivery: sent off the request path. A send happens only for an address that has
 * an account, and an SMTP round-trip is hundreds of milliseconds, so awaiting it made the response time answer
 * the question the uniform page refuses to. A failure is logged for the operator and is invisible to the
 * requester, as it was when awaited; the secret stays valid, so a retry after the cooldown costs nothing.
 */
function sendResetInBackground(
	to: string,
	appName: string,
	resetUrl: string,
	language: Language
): Promise<void> {
	void sendPasswordResetEmail({ email: to, appName, resetUrl, language }).catch(
		(err: unknown) => {
			console.error('password reset email could not be delivered:', err);
		}
	);
	return Promise.resolve();
}

/*
 * Handle a reset request for an address in one bucket.
 *
 * The outcome — `sent`, and a throttle refusal's reason — is for tests and logs only. The route renders the
 * same page for every one of them, the refusals included, because a response that varied with the outcome
 * would answer "does this address have an account here?" for anyone who asked. `sent` means queued: the
 * mail itself goes out after the response (see `issueAndSend`).
 */
export async function request(
	email: string,
	bucketId: string,
	language?: Language
): Promise<RequestOutcome> {
	/*
	 * The door refuses first and the sign-in page no longer links to it; this holds for any path that did
	 * not pass either. `resolveBucketForClient` maps the reserved console client straight to the admin
	 * bucket, so without it the console's own sign-in page would offer an unaudited credential change.
	 */
	const bucket = await getBucketStore().find(bucketId);
	if (
		!bucket ||
		isScheduledForDeletion(bucket) ||
		!selfServiceResetAllowed(bucketId, bucket)
	) {
		return { ok: true, sent: false };
	}

	const user = await getUserStore(bucketId).findByEmail(email);
	if (!user || !canSignIn(user)) {
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
		await issueAndSend(user, bucket, {
			purpose: 'reset',
			ttl: RESET_TTL_SECONDS,
			language,
			send: sendResetInBackground
		});
	} catch (err) {
		/*
		 * Issuing only happens for an address that *does* have an account here, so surfacing a failure to
		 * store the secret would answer the question the uniform response exists to refuse. Logged for the
		 * operator, invisible to the requester. A delivery failure never reaches here: the send is not awaited.
		 */
		console.error('password reset could not be issued:', err);
		return { ok: true, sent: false };
	}

	return { ok: true, sent: true };
}

export type LoadOutcome =
	| {
			ok: true;
			id: string;
			challenge: PasswordResetChallengePayload;
			purpose: SetPasswordPurpose;
			/* For the page's words: an invitation names the place the person is invited to. */
			bucketName: string;
	  }
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
	// Also a link issued before the bucket closed its password door: it must not set a password now.
	if (!selfServiceResetAllowed(challenge.bucketId, bucket)) {
		return { ok: false };
	}
	/* Nor one issued before the bucket was scheduled for deletion (specs/090): nobody signs in there. */
	if (bucket && isScheduledForDeletion(bucket)) {
		return { ok: false };
	}

	const user = await getUserStore(challenge.bucketId).find(challenge.accountId);
	if (!user || !canSignIn(user)) {
		return { ok: false };
	}
	/*
	 * A secret proves control of the mailbox it reached, and nothing else. Once the account's address changes,
	 * a link mailed to the old one must not set a password — nor mark the new address verified, which consuming
	 * does. The same rule, and the same indistinguishable refusal, as verification's `addressStillHeld`
	 * (lib/verification/challenge.ts).
	 */
	if (user.email.toLowerCase() !== challenge.email) {
		return { ok: false };
	}

	return {
		ok: true,
		id,
		challenge,
		purpose: challenge.purpose ?? 'reset',
		bucketName: bucket ? shownNameOf(bucket) : 'the application'
	};
}

export type ConsumeOutcome =
	| {
			ok: true;
			failedAreas: readonly string[];
			purpose: SetPasswordPurpose;
	  }
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
	/*
	 * Claimed in one insert-if-absent before anything is spent. Looking the secret up and then destroying
	 * it let two submissions arriving together both find it and both set a password; of several racing
	 * requests exactly one wins the claim, and the rest are answered as for a spent link.
	 */
	if (!(await ReplayDetection.unique('password-reset', id, challenge.exp))) {
		return { ok: false, reason: 'invalid' };
	}
	await challenges().destroy(id);
	await throttles().destroy(throttleKey(challenge.bucketId, challenge.email));

	await getUserStore(challenge.bucketId).update(challenge.accountId, {
		password: await Bun.password.hash(password),
		passwordSet: true,
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

	return {
		ok: true,
		failedAreas: swept.failedAreas,
		purpose: loaded.purpose
	};
}

export type InviteOutcome =
	| { outcome: 'sent' }
	| { outcome: 'rate_limited'; retryAfter: number }
	| { outcome: 'mail_not_configured' | 'delivery_failed' };

/*
 * Seconds until a message to this person may be sent again, or null when one may be sent now. The same
 * counters a reset request spends, so alternating the two is no way round either bound. For a caller that must
 * decide before it records anything: an administrator's invitation is audited first.
 */
export async function inviteRetryAfter(
	user: Pick<User, 'email'>,
	bucket: Pick<UserBucket, '_id'>
): Promise<number | null> {
	const prior = await throttles().find(throttleKey(bucket._id, user.email));
	const now = epochTime();
	const refusal = rateRefusal(prior, now, REQUEST_BOUNDS);
	if (!refusal || !prior) return null;
	const until =
		refusal === 'cooldown'
			? prior.lastSentAt + REQUEST_BOUNDS.cooldownSeconds
			: prior.windowStart + REQUEST_BOUNDS.windowSeconds;
	return Math.max(1, until - now);
}

/*
 * An administrator's invitation for a person to set their own password (specs/089): the reset's secret, with a
 * week's life and its own message. Awaited, unlike a self-service reset: the administrator chose the address
 * and must learn that the message did not go, and a secret whose message never left is destroyed, so the
 * person's page does not suggest a link is out there.
 *
 * The route refuses a provisioned person, a bucket without passwords and a person who cannot sign in before it
 * records anything; this asserts the same, so no other caller can mail a link that would set a password a
 * directory owns or that no door would accept.
 */
export async function invite(
	user: User,
	bucket: UserBucket
): Promise<InviteOutcome> {
	if (
		user.provisionedBy !== undefined ||
		!canSignIn(user) ||
		!selfServiceResetAllowed(bucket._id, bucket)
	) {
		throw new Error('this person cannot be invited to set a password');
	}

	const retryAfter = await inviteRetryAfter(user, bucket);
	if (retryAfter !== null) {
		return { outcome: 'rate_limited', retryAfter };
	}

	try {
		await issueAndSend(user, bucket, {
			purpose: 'invite',
			ttl: INVITE_TTL_SECONDS,
			send: (to, bucketName, url, language) =>
				sendUserInvitationEmail(to, { bucketName, url, language })
		});
		return { outcome: 'sent' };
	} catch (err) {
		const issued = await throttles().find(throttleKey(bucket._id, user.email));
		if (issued?.challengeId) await challenges().destroy(issued.challengeId);
		return {
			outcome:
				err instanceof MailNotConfiguredError
					? 'mail_not_configured'
					: 'delivery_failed'
		};
	}
}
