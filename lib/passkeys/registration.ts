import { randomBytes, randomInt } from 'node:crypto';

import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';

import {
	checkedAdapter,
	getPasskeyStore,
	getUserStore
} from '../adapters/index.js';
import {
	DuplicateEndUserError,
	type Passkey,
	type User,
	type UserBucket,
	type VerificationMethod
} from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { shownNameOf } from '../configs/issuer.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { routeNames } from '../consts/param_list.js';
import constantEquals from '../helpers/constant_equals.js';
import epochTime from '../helpers/epoch_time.js';
import { nextRateFields, rateRefusal } from '../helpers/rate_window.js';
import { unusablePassword } from '../helpers/unusable_password.js';
import type { Language } from '../i18n/languages.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import {
	passkeyRegistrationCodeEmail,
	passkeyRegistrationExistsEmail,
	passkeyRegistrationLinkEmail
} from '../mail/templates/passkeys.js';
import { admitMailRequest } from '../mail_limit/tally.js';
import { ReplayDetection } from '../models/replay_detection.js';
import { deviceOf } from '../person_activity/device.js';
import { signUpsPaused } from '../plans/signups.js';
import { digestOf } from '../totp/self_service.js';
import { passkeysAccepted } from './accepted.js';
import { notMeProject } from './account.js';
import { addOptions, readAttestation, verifyAdd } from './ceremony.js';
import {
	NOT_ME_SECONDS,
	PASSKEY_LINK_COOLDOWN_SECONDS,
	PASSKEY_LINK_DAILY_CAP,
	PASSKEY_LINK_WINDOW_SECONDS,
	REGISTRATION_CHALLENGE_SECONDS,
	REGISTRATION_CODE_MAX_ATTEMPTS
} from './consts.js';
import { notifyPasskey } from './notify.js';
import { relyingPartyOf } from './relying_party.js';
import {
	PasskeyLinkThrottlePayload,
	PasskeyRegistrationChallengePayload
} from './types.js';

/*
 * Pre-account passkey registration (specs/145 Q2=A, S4): verifies control of the submitted mailbox BEFORE creating any
 * account, honours the project's `verificationMethod` (`link` or `code`), and keeps taken addresses completely
 * indistinguishable on screen while emailing an informational notice and never modifying the existing account.
 */

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const THROTTLE_BOUNDS = {
	cooldownSeconds: PASSKEY_LINK_COOLDOWN_SECONDS,
	cap: PASSKEY_LINK_DAILY_CAP,
	windowSeconds: PASSKEY_LINK_WINDOW_SECONDS
};

function challenges() {
	return checkedAdapter(
		'PasskeyRegistrationChallenge',
		PasskeyRegistrationChallengePayload
	);
}

function throttles() {
	return checkedAdapter('PasskeyLinkThrottle', PasskeyLinkThrottlePayload);
}

export function registrationThrottleKey(
	bucketId: string,
	email: string
): string {
	return `reg:${bucketId}:${email.toLowerCase()}`;
}

function newCode(): string {
	return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

export type StartRegistrationOutcome =
	| {
			ok: true;
			id: string;
			email: string;
			method: VerificationMethod;
			exp: number;
	  }
	| { ok: false; reason: 'mail_limited'; retryAfter: number }
	| { ok: false; reason: 'invalid_email' | 'closed' | 'unavailable' };

export async function startPasskeyRegistration(input: {
	bucket: UserBucket;
	email: string;
	holder: string;
	language: Language;
	request: Request;
	linkUrlFor: (token: string) => string;
}): Promise<StartRegistrationOutcome> {
	// Caller-address rate limit ALWAYS precedes any account lookup (FR-007).
	const admission = await admitMailRequest(input.request);
	if (!admission.admitted) {
		return {
			ok: false,
			reason: 'mail_limited',
			retryAfter: admission.retryAfter
		};
	}

	const { bucket } = input;
	if (
		isScheduledForDeletion(bucket) ||
		!bucket.registrationOpen ||
		(await signUpsPaused(bucket))
	) {
		return { ok: false, reason: 'closed' };
	}
	if (!passkeysAccepted(bucket) || !(await mailDeliveryConfigured())) {
		return { ok: false, reason: 'unavailable' };
	}

	const normalized = input.email.trim().toLowerCase();
	if (!EMAIL_SHAPE.test(normalized)) {
		return { ok: false, reason: 'invalid_email' };
	}

	const now = epochTime();
	const method = bucket.verificationMethod;
	const exp = now + REGISTRATION_CHALLENGE_SECONDS;
	const key = registrationThrottleKey(bucket._id, normalized);
	const prior = await throttles().find(key);
	const livePrior = prior && prior.exp > now ? prior : undefined;

	// Silently suppress excess mail while returning an identical decoy challenge so throttles cannot enumerate.
	if (rateRefusal(livePrior, now, THROTTLE_BOUNDS)) {
		const decoyId = digestOf(randomBytes(32).toString('base64url'));
		await challenges().upsert(
			decoyId,
			{
				bucketId: bucket._id,
				email: normalized,
				holder: input.holder,
				method,
				exists: true,
				attempts: 0,
				language: input.language,
				exp
			},
			REGISTRATION_CHALLENGE_SECONDS
		);
		return { ok: true, id: decoyId, email: normalized, method, exp };
	}

	const existing = await getUserStore(bucket._id).findByEmail(normalized);
	const service = shownNameOf(bucket);
	const who = { service, email: normalized };

	if (livePrior?.challengeId) {
		await challenges().destroy(livePrior.challengeId);
	}

	if (existing) {
		const decoyId = digestOf(randomBytes(32).toString('base64url'));
		await challenges().upsert(
			decoyId,
			{
				bucketId: bucket._id,
				email: normalized,
				holder: input.holder,
				method,
				exists: true,
				attempts: 0,
				language: input.language,
				exp
			},
			REGISTRATION_CHALLENGE_SECONDS
		);
		const rate = nextRateFields(livePrior, now, THROTTLE_BOUNDS, true);
		await throttles().upsert(
			key,
			{
				...rate,
				challengeId: decoyId,
				exp: now + PASSKEY_LINK_WINDOW_SECONDS
			},
			PASSKEY_LINK_WINDOW_SECONDS
		);
		try {
			await deliver({
				to: normalized,
				...passkeyRegistrationExistsEmail(who, input.language)
			});
		} catch (error) {
			console.error('passkey registration: existing-account notice failed', {
				error
			});
		}
		return { ok: true, id: decoyId, email: normalized, method, exp };
	}

	const token = randomBytes(32).toString('base64url');
	const id = digestOf(token);
	const code = method === 'code' ? newCode() : undefined;

	await challenges().upsert(
		id,
		{
			bucketId: bucket._id,
			email: normalized,
			holder: input.holder,
			method,
			exists: false,
			...(code === undefined ? {} : { codeHash: digestOf(code) }),
			attempts: 0,
			language: input.language,
			exp
		},
		REGISTRATION_CHALLENGE_SECONDS
	);
	const rate = nextRateFields(livePrior, now, THROTTLE_BOUNDS, true);
	await throttles().upsert(
		key,
		{
			...rate,
			challengeId: id,
			exp: now + PASSKEY_LINK_WINDOW_SECONDS
		},
		PASSKEY_LINK_WINDOW_SECONDS
	);

	try {
		await deliver({
			to: normalized,
			...(method === 'link'
				? passkeyRegistrationLinkEmail(
						who,
						input.linkUrlFor(token),
						input.language
					)
				: passkeyRegistrationCodeEmail(who, code as string, input.language))
		});
	} catch (error) {
		console.error('passkey registration: verification email failed', { error });
	}

	return { ok: true, id, email: normalized, method, exp };
}

/*
 * Validates a registration link token without consuming it: the route is guarded by `_interaction`, so another browser
 * or mail scanner never reaches this check.
 */
export async function loadRegistrationLink(
	token: string,
	bucketId: string,
	holder: string
): Promise<
	{ id: string; challenge: PasskeyRegistrationChallengePayload } | undefined
> {
	if (!token) return undefined;
	const id = digestOf(token);
	const challenge = await challenges().find(id);
	if (
		!challenge ||
		challenge.method !== 'link' ||
		challenge.exists ||
		challenge.bucketId !== bucketId ||
		challenge.holder !== holder ||
		challenge.exp <= epochTime()
	) {
		return undefined;
	}
	return { id, challenge };
}

export type VerifyRegistrationCodeOutcome =
	| { ok: true; challenge: PasskeyRegistrationChallengePayload }
	| { ok: false; reason: 'invalid' | 'wrong' | 'too_many' };

export async function verifyRegistrationCode(
	id: string,
	code: string,
	bucketId: string,
	holder: string
): Promise<VerifyRegistrationCodeOutcome> {
	const challenge = await challenges().find(id);
	if (
		!challenge ||
		challenge.method !== 'code' ||
		challenge.bucketId !== bucketId ||
		challenge.holder !== holder ||
		challenge.exp <= epochTime()
	) {
		return { ok: false, reason: 'invalid' };
	}
	if (challenge.attempts >= REGISTRATION_CODE_MAX_ATTEMPTS) {
		return { ok: false, reason: 'too_many' };
	}
	const attempt = await challenges().increment(id, 'attempts');
	if (attempt === undefined) return { ok: false, reason: 'invalid' };
	if (attempt > REGISTRATION_CODE_MAX_ATTEMPTS) {
		return { ok: false, reason: 'too_many' };
	}
	const trimmed = code.trim();
	if (
		!challenge.exists &&
		challenge.codeHash !== undefined &&
		/^\d{6}$/.test(trimmed) &&
		constantEquals(challenge.codeHash, digestOf(trimmed))
	) {
		return { ok: true, challenge };
	}
	return {
		ok: false,
		reason: attempt >= REGISTRATION_CODE_MAX_ATTEMPTS ? 'too_many' : 'wrong'
	};
}

export interface PreparedRegistrationCeremony {
	userId: string;
	challenge: string;
	rpId: string;
	origin: string;
	options: PublicKeyCredentialCreationOptionsJSON;
}

export async function prepareRegistrationCeremony(
	bucket: UserBucket,
	email: string
): Promise<PreparedRegistrationCeremony> {
	const party = relyingPartyOf(bucket);
	const userId = randomBytes(32).toString('base64url');
	const challenge = randomBytes(32).toString('base64url');
	const options = await addOptions({
		rpId: party.rpId,
		rpName: party.name,
		userId,
		label: `${email} · ${party.name}`,
		challenge,
		exclude: []
	});
	return {
		userId,
		challenge,
		rpId: party.rpId,
		origin: party.origin,
		options
	};
}

export type CompleteRegistrationOutcome =
	| { ok: true; user: User; passkey: Passkey }
	| {
			ok: false;
			reason:
				'expired' | 'closed' | 'duplicate' | 'no_user_verification' | 'failed';
	  };

export async function completePasskeyRegistration(input: {
	bucket: UserBucket;
	challengeId: string;
	holder: string;
	ceremony: {
		userId: string;
		challenge: string;
		rpId: string;
		origin: string;
	};
	credential: string;
	request: Request;
}): Promise<CompleteRegistrationOutcome> {
	const { bucket, challengeId, holder, ceremony, credential, request } = input;
	if (
		isScheduledForDeletion(bucket) ||
		!bucket.registrationOpen ||
		(await signUpsPaused(bucket)) ||
		!passkeysAccepted(bucket)
	) {
		return { ok: false, reason: 'closed' };
	}

	const stored = await challenges().find(challengeId);
	if (
		!stored ||
		stored.exists ||
		stored.bucketId !== bucket._id ||
		stored.holder !== holder ||
		stored.exp <= epochTime()
	) {
		return { ok: false, reason: 'expired' };
	}

	const party = relyingPartyOf(bucket);
	if (party.rpId !== ceremony.rpId || party.origin !== ceremony.origin) {
		return { ok: false, reason: 'expired' };
	}

	const response = readAttestation(credential);
	if (!response) return { ok: false, reason: 'failed' };
	const verified = await verifyAdd(response, {
		rpId: ceremony.rpId,
		origin: ceremony.origin,
		challenge: ceremony.challenge,
		silent: false
	});
	if (!verified.ok) {
		return {
			ok: false,
			reason:
				verified.reason === 'no_user_verification'
					? 'no_user_verification'
					: 'failed'
		};
	}

	// Single-use claim before creating the account so concurrent submissions can succeed at most once.
	if (
		!(await ReplayDetection.unique(
			'passkey-registration',
			challengeId,
			stored.exp
		))
	) {
		return { ok: false, reason: 'expired' };
	}
	await challenges().destroy(challengeId);
	await throttles().destroy(registrationThrottleKey(bucket._id, stored.email));

	const userStore = getUserStore(bucket._id);
	let user: User;
	try {
		user = await userStore.create(
			stored.email,
			await unusablePassword(),
			true,
			undefined,
			{
				passwordSet: false,
				webauthnUserId: ceremony.userId
			}
		);
	} catch (error) {
		if (error instanceof DuplicateEndUserError) {
			return { ok: false, reason: 'duplicate' };
		}
		throw error;
	}

	const made = verified.passkey;
	const secret = randomBytes(32).toString('base64url');
	const createdOn = deviceOf(request.headers.get('user-agent')) ?? {
		browser: 'other' as const,
		system: 'other' as const
	};
	const record: Passkey = {
		_id: randomBytes(16).toString('base64url'),
		bucketId: bucket._id,
		accountId: user._id,
		credentialId: made.credentialId,
		publicKey: made.publicKey,
		rpId: ceremony.rpId,
		counter: made.counter,
		backupEligible: made.backupEligible,
		backedUp: made.backedUp,
		transports: made.transports,
		aaguid: made.aaguid,
		createdAt: new Date(),
		createdVia: 'registration',
		createdOn,
		notMe: { digest: digestOf(secret), exp: epochTime() + NOT_ME_SECONDS }
	};

	await recordEndUserAudit(bucket._id, user._id, 'enduser.passkey.add', {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
	const created = await getPasskeyStore().create(record);
	if (created === 'exists') {
		await userStore.destroy(user._id);
		return { ok: false, reason: 'failed' };
	}

	const disownUrl = `${accountPageBase(bucket)}${routeNames.account_passkey_disown}?token=${record._id}.${secret}${notMeProject(bucket)}`;
	await notifyPasskey(bucket, user, {
		kind: 'added',
		madeOn: createdOn,
		at: record.createdAt.getTime(),
		disownUrl
	});

	return { ok: true, user, passkey: record };
}
