import crypto from 'crypto';
import {
	checkedAdapter,
	getUserStore,
	getBucketStore
} from '../adapters/index.js';
import {
	VerificationChallengePayload,
	VerificationResendPayload
} from './types.js';
import type {
	User,
	UserBucket,
	VerificationMethod
} from '../adapters/types.js';
import { ISSUER } from '../configs/env.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import epochTime from '../helpers/epoch_time.js';
import {
	rateRefusal,
	nextRateFields,
	type RateBounds
} from '../helpers/rate_window.js';
import { sendVerificationEmail } from '../mail/send.js';
import { MailNotConfiguredError } from '../mail/mailer.js';
import {
	LINK_TTL_SECONDS,
	CODE_TTL_SECONDS,
	CODE_MAX_ATTEMPTS,
	RESEND_COOLDOWN_SECONDS,
	RESEND_DAILY_CAP,
	RESEND_WINDOW_SECONDS
} from './consts.js';

function challenges() {
	return checkedAdapter('VerificationChallenge', VerificationChallengePayload);
}

function resends() {
	return checkedAdapter('VerificationResend', VerificationResendPayload);
}

export function resendKey(bucketId: string, email: string): string {
	return emailScopedId(bucketId, email);
}

function ttlFor(method: VerificationMethod): number {
	return method === 'code' ? CODE_TTL_SECONDS : LINK_TTL_SECONDS;
}

function newToken(): string {
	return crypto.randomBytes(32).toString('base64url');
}

function newCode(): string {
	// 6-digit numeric OTP, zero-padded (000000–999999).
	return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function hashCode(code: string): string {
	return crypto.createHash('sha256').update(code).digest('hex');
}

export function verifyUrlFor(token: string): string {
	return `${ISSUER}/verify-email?token=${encodeURIComponent(token)}`;
}

// This flow's bounds for the shared window arithmetic (lib/helpers/rate_window.ts). The arithmetic is
// shared with the password-reset request because it is a security rule; the numbers stay here because the
// two flows limit different things.
const RESEND_BOUNDS: RateBounds = {
	cooldownSeconds: RESEND_COOLDOWN_SECONDS,
	cap: RESEND_DAILY_CAP,
	windowSeconds: RESEND_WINDOW_SECONDS
};

// Issue a fresh challenge for the account, superseding any outstanding one, and deliver
// the verification email. Throws if delivery fails. Returns the challenge id (the link
// token, or the `ref` for the code-entry page).
export async function issueAndSend(
	user: Pick<User, '_id' | 'email'>,
	bucket: Pick<UserBucket, '_id' | 'name' | 'verificationMethod'>,
	opts: { bumpRate?: boolean } = {}
): Promise<{ id: string; method: VerificationMethod }> {
	const method = bucket.verificationMethod;
	const key = resendKey(bucket._id, user.email);

	const prior = await resends().find(key);
	if (prior?.challengeId) {
		await challenges().destroy(prior.challengeId);
	}

	const id = newToken();
	const code = method === 'code' ? newCode() : undefined;
	const ttl = ttlFor(method);
	const exp = epochTime() + ttl;

	await challenges().upsert(
		id,
		{
			accountId: user._id,
			bucketId: bucket._id,
			email: user.email,
			method,
			...(code ? { codeHash: hashCode(code) } : {}),
			attempts: 0,
			exp
		},
		ttl
	);

	const rate = nextRateFields(
		prior,
		epochTime(),
		RESEND_BOUNDS,
		opts.bumpRate ?? false
	);
	await resends().upsert(
		key,
		{ ...rate, challengeId: id, exp: epochTime() + RESEND_WINDOW_SECONDS },
		RESEND_WINDOW_SECONDS
	);

	const appName = bucket.name || 'the application';
	await sendVerificationEmail({
		email: user.email,
		appName,
		method,
		verifyUrl: method === 'link' ? verifyUrlFor(id) : undefined,
		code
	});

	return { id, method };
}

export type VerifyOutcome = { ok: true } | { ok: false; reason: 'invalid' };

// Consume a link token: mark the bound account verified and delete the challenge so it
// cannot be reused. Unknown/expired/already-used tokens fail as 'invalid'.
export async function verifyLink(token: string): Promise<VerifyOutcome> {
	const challenge = await challenges().find(token);
	if (!challenge || challenge.method !== 'link') {
		return { ok: false, reason: 'invalid' };
	}
	await getUserStore(challenge.bucketId).update(challenge.accountId, {
		verified: true
	});
	await challenges().destroy(token);
	await resends().destroy(resendKey(challenge.bucketId, challenge.email));
	return { ok: true };
}

export type CodeOutcome =
	{ ok: true } | { ok: false; reason: 'invalid' | 'wrong' | 'too_many' };

// Verify a submitted 6-digit code against the challenge identified by `ref`. Counts wrong
// attempts and, once the cap is reached, refuses even a correct code until a new one is
// requested.
export async function verifyCode(
	ref: string,
	code: string
): Promise<CodeOutcome> {
	const challenge = await challenges().find(ref);
	/*
	 * Expiry compared here as well as reaped by the store: MongoDB's TTL monitor deletes lazily, and a
	 * code that outlived its window by a minute is a minute of guessing nobody granted.
	 */
	if (
		!challenge ||
		challenge.method !== 'code' ||
		challenge.exp <= epochTime()
	) {
		return { ok: false, reason: 'invalid' };
	}
	if (challenge.attempts >= CODE_MAX_ATTEMPTS) {
		return { ok: false, reason: 'too_many' };
	}
	/*
	 * The attempt is counted before the code is compared, in one atomic write that answers this
	 * attempt's own number. Counting a wrong guess after comparing it was a read-modify-write: a burst
	 * of parallel guesses all read the same count and together advanced it by one, so the cap never
	 * bound. A right code is counted too, harmlessly — the challenge is destroyed with it.
	 */
	const attempt = await challenges().increment(ref, 'attempts');
	if (attempt === undefined) {
		return { ok: false, reason: 'invalid' };
	}
	if (attempt > CODE_MAX_ATTEMPTS) {
		return { ok: false, reason: 'too_many' };
	}
	if (challenge.codeHash === hashCode(code)) {
		await getUserStore(challenge.bucketId).update(challenge.accountId, {
			verified: true
		});
		await challenges().destroy(ref);
		await resends().destroy(resendKey(challenge.bucketId, challenge.email));
		return { ok: true };
	}

	return {
		ok: false,
		reason: attempt >= CODE_MAX_ATTEMPTS ? 'too_many' : 'wrong'
	};
}

export type ResendOutcome =
	| { ok: true; sent: boolean; method?: VerificationMethod; newRef?: string }
	| { ok: false; reason: 'cooldown' | 'daily' };

// Re-issue and re-send a challenge for the account behind `ref` (the current or a just-
// expired challenge). Enforces the per-account cooldown + daily cap; over-limit requests
// are refused and send no email.
export async function resend(ref: string): Promise<ResendOutcome> {
	const challenge = await challenges().find(ref);
	// Nothing to resend (already verified/consumed or unknown): non-committal success.
	if (!challenge) return { ok: true, sent: false };

	const { bucketId, accountId, email } = challenge;
	const prior = await resends().find(resendKey(bucketId, email));
	const refusal = rateRefusal(prior, epochTime(), RESEND_BOUNDS);
	if (refusal) {
		return { ok: false, reason: refusal };
	}

	const bucket = await getBucketStore().find(bucketId);
	const user = await getUserStore(bucketId).find(accountId);
	if (!bucket || !user || user.verified) {
		return { ok: true, sent: false };
	}

	const { id, method } = await issueAndSend(user, bucket, { bumpRate: true });
	return { ok: true, sent: true, method, newRef: id };
}

export type OnDemandOutcome =
	| { outcome: 'sent' | 'outstanding'; method: VerificationMethod; id: string }
	| { outcome: 'rate_limited' | 'delivery_failed' | 'mail_not_configured' };

/*
 * A verification message for an account that asked for one without a challenge reference in hand: a
 * password sign-in refused for an unverified address, or an administrator pressing "verify my address".
 *
 * Without this the sign-in only said "check your inbox", which was true for a fresh registrant and false
 * for every account that existed before its bucket required verification — nothing had ever been sent to
 * them, and the administrators' bucket could not require verification at all while that stayed true.
 *
 * `reuseOutstanding` is the sign-in's choice. A registrant who signs in before following their link must
 * not have it replaced under them, since issuing supersedes the outstanding challenge; so a live one is
 * answered as outstanding and nothing is sent. The console's button asks for a fresh message, because the
 * person pressing it is saying the last one did not reach them.
 *
 * Within the existing cooldown and daily cap either way, so neither door is a way to flood a mailbox.
 */
export async function sendOnDemand(
	user: Pick<User, '_id' | 'email'>,
	bucket: Pick<UserBucket, '_id' | 'name' | 'verificationMethod'>,
	opts: { reuseOutstanding: boolean }
): Promise<OnDemandOutcome> {
	const key = resendKey(bucket._id, user.email);
	const prior = await resends().find(key);

	if (opts.reuseOutstanding && prior?.challengeId) {
		const live = await challenges().find(prior.challengeId);
		if (
			live &&
			live.exp > epochTime() &&
			live.method === bucket.verificationMethod
		) {
			return {
				outcome: 'outstanding',
				method: live.method,
				id: prior.challengeId
			};
		}
	}

	if (rateRefusal(prior, epochTime(), RESEND_BOUNDS)) {
		return { outcome: 'rate_limited' };
	}

	try {
		const { id, method } = await issueAndSend(user, bucket, {
			bumpRate: true
		});
		return { outcome: 'sent', method, id };
	} catch (err) {
		/*
		 * The challenge was stored before delivery failed. Left in place, the next sign-in would find it
		 * live and answer "check your inbox" for a message that never left.
		 */
		const issued = await resends().find(key);
		if (issued?.challengeId) await challenges().destroy(issued.challengeId);
		return {
			outcome:
				err instanceof MailNotConfiguredError
					? 'mail_not_configured'
					: 'delivery_failed'
		};
	}
}

export { hashCode, newCode };
