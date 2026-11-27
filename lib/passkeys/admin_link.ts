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
import { shownNameOf } from '../configs/issuer.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { routeNames } from '../consts/param_list.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { ensurePasskeyIdentity } from '../end_users/service.js';
import epochTime from '../helpers/epoch_time.js';
import { nextRateFields, rateRefusal } from '../helpers/rate_window.js';
import { emailLanguage } from '../i18n/resolve.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import { passkeyAdminSetupEmail } from '../mail/templates/passkeys.js';
import { ReplayDetection } from '../models/replay_detection.js';
import { deviceOf } from '../person_activity/device.js';
import { digestOf } from '../totp/self_service.js';
import { passkeysAccepted } from './accepted.js';
import { notMeProject } from './account.js';
import {
	ceremonyId,
	liveCeremony,
	prepareCeremony,
	takeCeremony
} from './ceremonies.js';
import { addOptions, readAttestation, verifyAdd } from './ceremony.js';
import {
	ADMIN_LINK_SECONDS,
	EMAIL_CHANGE_LINK_COOLDOWN_SECONDS,
	NOT_ME_SECONDS,
	PASSKEY_LINK_COOLDOWN_SECONDS,
	PASSKEY_LINK_DAILY_CAP,
	PASSKEY_LINK_WINDOW_SECONDS,
	PASSKEYS_PER_PERSON
} from './consts.js';
import { notifyPasskey } from './notify.js';
import { relyingPartyOf } from './relying_party.js';
import {
	PasskeyAdminLinkPayload,
	PasskeyLinkThrottlePayload
} from './types.js';

/*
 * Administrator-sent passkey enrollment links (specs/145 S14): 24-hour, single-use, any-browser links delivered
 * strictly by email (never returned in API/MCP/audit responses). Refused when email is unverified or changed within
 * the last 7 days, and requires TOTP on the link page whenever the target has an authenticator app enrolled.
 */

const THROTTLE_BOUNDS = {
	cooldownSeconds: PASSKEY_LINK_COOLDOWN_SECONDS,
	cap: PASSKEY_LINK_DAILY_CAP,
	windowSeconds: PASSKEY_LINK_WINDOW_SECONDS
};

function links() {
	return checkedAdapter('PasskeyAdminLink', PasskeyAdminLinkPayload);
}

function throttles() {
	return checkedAdapter('PasskeyLinkThrottle', PasskeyLinkThrottlePayload);
}

export function adminLinkThrottleKey(
	bucketId: string,
	accountId: string
): string {
	return `adm:${bucketId}:${accountId}`;
}

export type SendAdminLinkCheck =
	| { ok: true }
	| {
			ok: false;
			status: 409 | 429;
			message: string;
			code?: string;
			retryAfter?: number;
	  };

export async function checkAdminPasskeyLinkEligibility(
	bucket: UserBucket,
	user: User,
	nowMs: number = Date.now()
): Promise<SendAdminLinkCheck> {
	if (!passkeysAccepted(bucket)) {
		return {
			ok: false,
			status: 409,
			message: 'Turn on Passkeys for this project before sending a setup link.',
			code: 'passkeys_not_accepted'
		};
	}
	if (!canSignIn(user)) {
		return {
			ok: false,
			status: 409,
			message:
				'Cannot send a passkey setup link to an account that cannot sign in.'
		};
	}
	if (!user.verified || !user.email) {
		return {
			ok: false,
			status: 409,
			message:
				"Verify the account's email address before sending a passkey setup link."
		};
	}
	if (user.emailChangedAt !== undefined) {
		const elapsedSeconds = Math.floor(
			(nowMs - new Date(user.emailChangedAt).getTime()) / 1000
		);
		if (elapsedSeconds < EMAIL_CHANGE_LINK_COOLDOWN_SECONDS) {
			return {
				ok: false,
				status: 409,
				message:
					'This email address was changed within the last 7 days; wait until 7 days have passed before sending a passkey setup link.',
				code: 'email_changed_recently'
			};
		}
	}
	if (!(await mailDeliveryConfigured())) {
		return {
			ok: false,
			status: 409,
			message: 'Mail delivery is not configured, so no message can be sent.'
		};
	}
	if (
		(await getPasskeyStore().countOf(bucket._id, user._id)) >=
		PASSKEYS_PER_PERSON
	) {
		return {
			ok: false,
			status: 409,
			message: 'This account already has the maximum of 20 passkeys.'
		};
	}
	const now = Math.floor(nowMs / 1000);
	const prior = await throttles().find(
		adminLinkThrottleKey(bucket._id, user._id)
	);
	const live = prior && prior.exp > now ? prior : undefined;
	const refusal = rateRefusal(live, now, THROTTLE_BOUNDS);
	if (refusal && live) {
		const until =
			refusal === 'cooldown'
				? live.lastSentAt + THROTTLE_BOUNDS.cooldownSeconds
				: live.windowStart + THROTTLE_BOUNDS.windowSeconds;
		return {
			ok: false,
			status: 429,
			message: 'A passkey setup link was sent recently. Try again later.',
			retryAfter: Math.max(1, until - now)
		};
	}
	return { ok: true };
}

export async function issueAdminPasskeyLink(
	bucket: UserBucket,
	user: User,
	sentBy: string
): Promise<{ ok: true } | { ok: false; reason: 'delivery_failed' }> {
	const now = epochTime();
	const key = adminLinkThrottleKey(bucket._id, user._id);
	const prior = await throttles().find(key);
	const live = prior && prior.exp > now ? prior : undefined;
	if (live?.challengeId) {
		await links().destroy(live.challengeId);
	}

	const token = randomBytes(32).toString('base64url');
	const id = digestOf(token);
	const language = emailLanguage(user);

	await links().upsert(
		id,
		{
			accountId: user._id,
			bucketId: bucket._id,
			email: user.email.toLowerCase(),
			sentBy,
			language,
			exp: now + ADMIN_LINK_SECONDS
		},
		ADMIN_LINK_SECONDS
	);

	const rate = nextRateFields(live, now, THROTTLE_BOUNDS, true);
	const throttleTtl = Math.max(PASSKEY_LINK_WINDOW_SECONDS, ADMIN_LINK_SECONDS);
	await throttles().upsert(
		key,
		{
			...rate,
			challengeId: id,
			exp: now + throttleTtl
		},
		throttleTtl
	);

	const url = `${accountPageBase(bucket)}${routeNames.account_passkey_setup}?token=${encodeURIComponent(token)}${notMeProject(bucket)}`;
	try {
		await deliver({
			to: user.email,
			...passkeyAdminSetupEmail(
				{ service: shownNameOf(bucket), email: user.email },
				url,
				language
			)
		});
		return { ok: true };
	} catch (error) {
		console.error('admin passkey setup link could not be delivered:', {
			accountId: user._id,
			error
		});
		await links().destroy(id);
		return { ok: false, reason: 'delivery_failed' };
	}
}

export async function loadAdminPasskeyLink(
	token: string,
	bucket: UserBucket | null
): Promise<
	{ id: string; record: PasskeyAdminLinkPayload; user: User } | undefined
> {
	if (
		!token ||
		!bucket ||
		isScheduledForDeletion(bucket) ||
		!passkeysAccepted(bucket)
	) {
		return undefined;
	}
	const id = digestOf(token);
	const record = await links().find(id);
	if (!record || record.exp <= epochTime() || record.bucketId !== bucket._id) {
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

export async function getAdminLinkCeremony(
	holder: string,
	linkId: string,
	bucketId: string,
	accountId: string
) {
	const ceremony = await liveCeremony(ceremonyId('admin_link', holder));
	return ceremony?.purpose === 'admin_link' &&
		ceremony.holder === holder &&
		ceremony.linkId === linkId &&
		ceremony.bucketId === bucketId &&
		ceremony.accountId === accountId
		? ceremony
		: undefined;
}

export async function markAdminLinkTotpVerified(
	bucket: UserBucket,
	user: User,
	holder: string,
	linkId: string
): Promise<void> {
	await prepareCeremony(ceremonyId('admin_link', holder), {
		accountId: user._id,
		bucketId: bucket._id,
		holder,
		purpose: 'admin_link',
		proof: 'admin_link',
		linkId,
		totpVerified: true
	});
}

export async function prepareAdminLinkCreation(
	bucket: UserBucket,
	user: User,
	holder: string,
	linkId: string,
	totpVerified: boolean
): Promise<PublicKeyCredentialCreationOptionsJSON> {
	const userId = await ensurePasskeyIdentity(bucket._id, user._id);
	const party = relyingPartyOf(bucket);
	const challenge = randomBytes(32).toString('base64url');
	await prepareCeremony(ceremonyId('admin_link', holder), {
		accountId: user._id,
		bucketId: bucket._id,
		holder,
		purpose: 'admin_link',
		proof: 'admin_link',
		linkId,
		totpVerified,
		challenge,
		userId,
		rpId: party.rpId,
		origin: party.origin
	});
	const held = await getPasskeyStore().listOf(bucket._id, user._id);
	return addOptions({
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
}

export type CompleteAdminLinkOutcome =
	| { ok: true; passkey: Passkey; user: User }
	| {
			ok: false;
			reason:
				| 'invalid'
				| 'totp_required'
				| 'expired'
				| 'exists'
				| 'no_user_verification'
				| 'failed';
	  };

export async function completeAdminPasskeyLink(input: {
	bucket: UserBucket | null;
	token: string;
	holder: string;
	credential: string;
	request: Request;
}): Promise<CompleteAdminLinkOutcome> {
	const { bucket, token, holder, credential, request } = input;
	const loaded = await loadAdminPasskeyLink(token, bucket);
	if (!loaded || !bucket) return { ok: false, reason: 'invalid' };
	const { id, record, user } = loaded;

	const ceremony = await takeCeremony(ceremonyId('admin_link', holder), holder);
	if (
		!ceremony ||
		ceremony.purpose !== 'admin_link' ||
		ceremony.linkId !== id ||
		ceremony.accountId !== user._id ||
		ceremony.bucketId !== bucket._id ||
		ceremony.challenge === undefined ||
		ceremony.rpId === undefined ||
		ceremony.origin === undefined ||
		ceremony.userId === undefined
	) {
		return { ok: false, reason: 'expired' };
	}

	if (user.totp !== undefined && ceremony.totpVerified !== true) {
		return { ok: false, reason: 'totp_required' };
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

	const store = getPasskeyStore();
	const made = verified.passkey;
	if (await store.findByCredential(bucket._id, made.credentialId)) {
		return { ok: false, reason: 'exists' };
	}

	if (!(await ReplayDetection.unique('passkey-admin-link', id, record.exp))) {
		return { ok: false, reason: 'invalid' };
	}
	await links().destroy(id);
	await throttles().destroy(adminLinkThrottleKey(bucket._id, user._id));

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
		createdAt: new Date(),
		createdVia: 'admin_link',
		createdOn,
		notMe: { digest: digestOf(secret), exp: epochTime() + NOT_ME_SECONDS }
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

	return { ok: true, passkey, user };
}
