import { randomBytes } from 'node:crypto';

import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';

import {
	checkedAdapter,
	getPasskeyStore,
	getUserStore
} from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { shownNameOf } from '../configs/issuer.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { routeNames } from '../consts/param_list.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { ensurePasskeyIdentity } from '../end_users/service.js';
import epochTime from '../helpers/epoch_time.js';
import { nextRateFields, rateRefusal } from '../helpers/rate_window.js';
import type { Language } from '../i18n/languages.js';
import { emailLanguage } from '../i18n/resolve.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import { passkeyRecoveryEmail } from '../mail/templates/passkeys.js';
import { admitMailRequest } from '../mail_limit/tally.js';
import { ReplayDetection } from '../models/replay_detection.js';
import { deviceOf } from '../person_activity/device.js';
import { digestOf } from '../totp/self_service.js';
import { passkeysAccepted } from './accepted.js';
import { notMeProject } from './account.js';
import { addOptions, readAttestation, verifyAdd } from './ceremony.js';
import {
	NOT_ME_SECONDS,
	PASSKEY_LINK_COOLDOWN_SECONDS,
	PASSKEY_LINK_DAILY_CAP,
	PASSKEY_LINK_WINDOW_SECONDS,
	PASSKEYS_PER_PERSON,
	RECOVERY_ACR_CAP_SECONDS,
	RECOVERY_LINK_SECONDS
} from './consts.js';
import { notifyPasskey } from './notify.js';
import { relyingPartyOf } from './relying_party.js';
import {
	PasskeyLinkThrottlePayload,
	PasskeyRecoveryChallengePayload
} from './types.js';

/*
 * Self-service passkey recovery ("Forgot your passkey?", specs/145 Q1=A, S3): opt-in on non-admin projects (never
 * available on `ADMIN_BUCKET_ID`), browser-bound single-use 10-minute email link, mandatory TOTP gate whenever
 * enrolled, no auto-sign-in, and a 72-hour `multi_factor` ACR cap lifted early if confirmed by another full passkey.
 */

const THROTTLE_BOUNDS = {
	cooldownSeconds: PASSKEY_LINK_COOLDOWN_SECONDS,
	cap: PASSKEY_LINK_DAILY_CAP,
	windowSeconds: PASSKEY_LINK_WINDOW_SECONDS
};

function challenges() {
	return checkedAdapter(
		'PasskeyRecoveryChallenge',
		PasskeyRecoveryChallengePayload
	);
}

function throttles() {
	return checkedAdapter('PasskeyLinkThrottle', PasskeyLinkThrottlePayload);
}

export function recoveryThrottleKey(bucketId: string, email: string): string {
	return `rec:${bucketId}:${email.toLowerCase()}`;
}

export function selfServicePasskeyRecoveryAllowed(
	bucket: UserBucket | null
): boolean {
	return (
		bucket !== null &&
		bucket._id !== ADMIN_BUCKET_ID &&
		!isScheduledForDeletion(bucket) &&
		passkeysAccepted(bucket) &&
		bucket.passkeyRecovery === true
	);
}

export type RequestRecoveryOutcome =
	| { ok: true; sent: boolean }
	| { ok: false; reason: 'mail_limited'; retryAfter: number };

export async function requestPasskeyRecovery(input: {
	bucket: UserBucket | null;
	email: string;
	holder: string;
	language: Language;
	request: Request;
	urlFor: (token: string) => string;
}): Promise<RequestRecoveryOutcome> {
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
		!bucket ||
		!selfServicePasskeyRecoveryAllowed(bucket) ||
		!(await mailDeliveryConfigured())
	) {
		return { ok: true, sent: false };
	}

	const normalized = input.email.trim().toLowerCase();
	if (!normalized) return { ok: true, sent: false };

	const user = await getUserStore(bucket._id).findByEmail(normalized);
	if (!user || !canSignIn(user) || !user.verified) {
		return { ok: true, sent: false };
	}

	const now = epochTime();
	const key = recoveryThrottleKey(bucket._id, user.email);
	const prior = await throttles().find(key);
	const livePrior = prior && prior.exp > now ? prior : undefined;
	if (rateRefusal(livePrior, now, THROTTLE_BOUNDS)) {
		return { ok: true, sent: false };
	}

	if (livePrior?.challengeId) {
		await challenges().destroy(livePrior.challengeId);
	}

	const token = randomBytes(32).toString('base64url');
	const id = digestOf(token);
	const language = emailLanguage(user, input.language);

	await challenges().upsert(
		id,
		{
			accountId: user._id,
			bucketId: bucket._id,
			email: user.email.toLowerCase(),
			holder: input.holder,
			language,
			exp: now + RECOVERY_LINK_SECONDS
		},
		RECOVERY_LINK_SECONDS
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

	// Sent off the request path so SMTP latency never distinguishes existing from unknown addresses.
	const emailMsg = passkeyRecoveryEmail(
		{ service: shownNameOf(bucket), email: user.email },
		input.urlFor(token),
		language
	);
	void deliver({ to: user.email, ...emailMsg }).catch((error: unknown) => {
		console.error('passkey recovery email could not be delivered:', error);
	});

	return { ok: true, sent: true };
}

export async function loadRecoveryLink(
	token: string,
	bucket: UserBucket | null,
	holder: string
): Promise<
	| { id: string; record: PasskeyRecoveryChallengePayload; user: User }
	| undefined
> {
	if (!token || !bucket || !selfServicePasskeyRecoveryAllowed(bucket)) {
		return undefined;
	}
	const id = digestOf(token);
	const record = await challenges().find(id);
	if (
		!record ||
		record.exp <= epochTime() ||
		record.bucketId !== bucket._id ||
		record.holder !== holder
	) {
		return undefined;
	}
	const user = await getUserStore(bucket._id).find(record.accountId);
	if (
		!user ||
		!canSignIn(user) ||
		!user.verified ||
		user.email.toLowerCase() !== record.email
	) {
		return undefined;
	}
	if (
		(await getPasskeyStore().countOf(bucket._id, user._id)) >=
		PASSKEYS_PER_PERSON
	) {
		return undefined;
	}
	return { id, record, user };
}

export async function prepareRecoveryCeremony(
	bucket: UserBucket,
	user: User
): Promise<{
	userId: string;
	challenge: string;
	rpId: string;
	origin: string;
	options: PublicKeyCredentialCreationOptionsJSON;
}> {
	const userId = await ensurePasskeyIdentity(bucket._id, user._id);
	const party = relyingPartyOf(bucket);
	const challenge = randomBytes(32).toString('base64url');
	const held = await getPasskeyStore().listOf(bucket._id, user._id);
	const options = await addOptions({
		rpId: party.rpId,
		rpName: party.name,
		userId,
		label: `${user.email} · ${party.name}`,
		challenge,
		exclude: held.map((passkey) => ({
			credentialId: passkey.credentialId,
			transports: passkey.transports
		}))
	});
	return { userId, challenge, rpId: party.rpId, origin: party.origin, options };
}

export type CompleteRecoveryOutcome =
	| { ok: true; passkey: Passkey }
	| {
			ok: false;
			reason:
				| 'expired'
				| 'totp_required'
				| 'exists'
				| 'full'
				| 'no_user_verification'
				| 'failed';
	  };

export async function completePasskeyRecovery(input: {
	bucket: UserBucket | null;
	challengeId: string;
	holder: string;
	totpVerified: boolean;
	ceremony: {
		userId: string;
		challenge: string;
		rpId: string;
		origin: string;
	};
	credential: string;
	request: Request;
}): Promise<CompleteRecoveryOutcome> {
	const {
		bucket,
		challengeId,
		holder,
		totpVerified,
		ceremony,
		credential,
		request
	} = input;
	if (!bucket || !selfServicePasskeyRecoveryAllowed(bucket)) {
		return { ok: false, reason: 'expired' };
	}

	const record = await challenges().find(challengeId);
	if (
		!record ||
		record.exp <= epochTime() ||
		record.bucketId !== bucket._id ||
		record.holder !== holder
	) {
		return { ok: false, reason: 'expired' };
	}

	const user = await getUserStore(bucket._id).find(record.accountId);
	if (
		!user ||
		!canSignIn(user) ||
		!user.verified ||
		user.email.toLowerCase() !== record.email
	) {
		return { ok: false, reason: 'expired' };
	}

	// Mandatory TOTP gate whenever enrolled, regardless of bucket.totpRequired (FR-011).
	if (user.totp !== undefined && !totpVerified) {
		return { ok: false, reason: 'totp_required' };
	}

	const store = getPasskeyStore();
	if ((await store.countOf(bucket._id, user._id)) >= PASSKEYS_PER_PERSON) {
		return { ok: false, reason: 'full' };
	}

	const party = relyingPartyOf(bucket);
	if (
		user.webauthnUserId !== ceremony.userId ||
		party.rpId !== ceremony.rpId ||
		party.origin !== ceremony.origin
	) {
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

	const made = verified.passkey;
	if (await store.findByCredential(bucket._id, made.credentialId)) {
		return { ok: false, reason: 'exists' };
	}

	if (
		!(await ReplayDetection.unique('passkey-recovery', challengeId, record.exp))
	) {
		return { ok: false, reason: 'expired' };
	}
	await challenges().destroy(challengeId);
	await throttles().destroy(recoveryThrottleKey(bucket._id, record.email));

	const nowDate = new Date();
	const secret = randomBytes(32).toString('base64url');
	const createdOn = deviceOf(request.headers.get('user-agent')) ?? {
		browser: 'other' as const,
		system: 'other' as const
	};
	const passkey: Passkey = {
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
		createdAt: nowDate,
		createdVia: 'recovery',
		createdOn,
		notMe: { digest: digestOf(secret), exp: epochTime() + NOT_ME_SECONDS },
		recoveredUntil: new Date(
			nowDate.getTime() + RECOVERY_ACR_CAP_SECONDS * 1000
		)
	};

	await recordEndUserAudit(bucket._id, user._id, 'enduser.passkey.add', {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
	if ((await store.create(passkey)) === 'exists') {
		return { ok: false, reason: 'exists' };
	}

	const disownUrl = `${accountPageBase(bucket)}${routeNames.account_passkey_disown}?token=${passkey._id}.${secret}${notMeProject(bucket)}`;
	await notifyPasskey(bucket, user, {
		kind: 'added',
		madeOn: createdOn,
		at: passkey.createdAt.getTime(),
		disownUrl
	});

	return { ok: true, passkey };
}
