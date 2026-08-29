import crypto from 'crypto';
import { adapter, getUserStore, getBucketStore } from '../adapters/index.js';
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
import {
	LINK_TTL_SECONDS,
	CODE_TTL_SECONDS,
	CODE_MAX_ATTEMPTS,
	RESEND_COOLDOWN_SECONDS,
	RESEND_DAILY_CAP,
	RESEND_WINDOW_SECONDS
} from './consts.js';
import type { VerificationResendPayload } from './types.js';

type ResendRecord = VerificationResendPayload & { challengeId?: string };

function challenges() {
	return adapter('VerificationChallenge');
}

function resends() {
	return adapter('VerificationResend');
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

	const prior = (await resends().find(key)) as ResendRecord | undefined;
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
	if (!challenge || challenge.method !== 'code') {
		return { ok: false, reason: 'invalid' };
	}
	if (challenge.attempts >= CODE_MAX_ATTEMPTS) {
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

	const attempts = challenge.attempts + 1;
	const remainingTtl = Math.max(1, challenge.exp - epochTime());
	await challenges().upsert(ref, { ...challenge, attempts }, remainingTtl);
	return {
		ok: false,
		reason: attempts >= CODE_MAX_ATTEMPTS ? 'too_many' : 'wrong'
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
	const prior = (await resends().find(resendKey(bucketId, email))) as
		ResendRecord | undefined;
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

export { hashCode, newCode };
