import { randomBytes } from 'node:crypto';

import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';

import { getBucketStore, getPasskeyStore } from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { routeNames } from '../consts/param_list.js';
import { addressOf, type RequestBucket } from '../configs/issuer.js';
import { ensurePasskeyIdentity } from '../end_users/service.js';
import epochTime from '../helpers/epoch_time.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import { deviceOf } from '../person_activity/device.js';
import { digestOf } from '../totp/self_service.js';
import { passkeysAccepted } from './accepted.js';
import {
	ceremonyId,
	liveCeremony,
	prepareCeremony,
	takeCeremony
} from './ceremonies.js';
import { addOptions, readAttestation, verifyAdd } from './ceremony.js';
import { NAME_MAX, NOT_ME_SECONDS, PASSKEYS_PER_PERSON } from './consts.js';
import { notifyPasskey } from './notify.js';
import { relyingPartyOf } from './relying_party.js';
import type { PasskeyCeremonyPayload } from './types.js';

/*
 * A person's own passkeys on their "Sign-in and security" page (specs/139 contracts/account-page.md): whether they may
 * add one, the add ceremony from its preparation to the stored record, the mail and the audit entry. The page decides
 * which proof it holds (lib/account_page/security_routes.ts); nothing here raises the session (FR-023).
 */

/* The browser session a ceremony belongs to: its id, and the holder value a mailed link is bound to. */
export interface PageSession {
	uid: string;
	holder: string;
}

/* The proof an add is made under, which the passkey keeps as `createdVia` (FR-026). */
export type AddProof = PasskeyCeremonyPayload['proof'];

/*
 * Whether this person may add a passkey here now, and if not why (FR-021), in the order the page explains them: the
 * project must accept passkeys; a person with neither a password nor a passkey signs in only through a provider,
 * whose account could be someone else's mailbox too; every add is mailed about, so mail must work and the address
 * must be confirmed; twenty at most.
 */
export type AddAvailability =
	| 'not_accepted'
	| 'provider_only'
	| 'no_mail'
	| 'unconfirmed'
	| 'full'
	| 'ready';

export async function addAvailability(
	bucket: UserBucket,
	user: User,
	held: number
): Promise<AddAvailability> {
	if (!passkeysAccepted(bucket)) return 'not_accepted';
	if (user.passwordSet === false && held === 0) return 'provider_only';
	if (!(await mailDeliveryConfigured())) return 'no_mail';
	if (!user.verified) return 'unconfirmed';
	if (held >= PASSKEYS_PER_PERSON) return 'full';
	return 'ready';
}

/* The person's passkeys in this project, oldest first, as their page lists them. */
export async function passkeysOf(
	bucket: UserBucket,
	user: User
): Promise<Passkey[]> {
	const held = await getPasskeyStore().listOf(bucket._id, user._id);
	return held.sort(
		(a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
	);
}

/* The add this browser session prepared and has not spent yet, or none. */
export async function liveAdd(
	user: User,
	bucket: UserBucket,
	session: PageSession
): Promise<PasskeyCeremonyPayload | undefined> {
	const ceremony = await liveCeremony(ceremonyId('add', session.uid));
	return ceremony?.purpose === 'add' &&
		ceremony.holder === session.holder &&
		ceremony.accountId === user._id &&
		ceremony.bucketId === bucket._id
		? ceremony
		: undefined;
}

/*
 * Prepares an add for this browser session (research R15): the person's passkey identity (created on the first add),
 * a challenge, and the one RP ID and origin of the project, kept for five minutes. Replaces the session's earlier add.
 */
export async function prepareAdd(
	bucket: UserBucket,
	user: User,
	session: PageSession,
	proof: AddProof
): Promise<PasskeyCeremonyPayload> {
	const userId = await ensurePasskeyIdentity(bucket._id, user._id);
	const party = relyingPartyOf(bucket);
	return prepareCeremony(ceremonyId('add', session.uid), {
		accountId: user._id,
		bucketId: bucket._id,
		holder: session.holder,
		purpose: 'add',
		proof,
		challenge: randomBytes(32).toString('base64url'),
		userId,
		rpId: party.rpId,
		origin: party.origin
	});
}

/*
 * The options the page hands the browser for a prepared add. The browser lists the passkey as "{email} · {project}"
 * (FR-009) and declines to make a second one on a device that already holds one of the person's passkeys here.
 */
export async function creationOptionsFor(
	bucket: UserBucket,
	user: User,
	ceremony: PasskeyCeremonyPayload
): Promise<PublicKeyCredentialCreationOptionsJSON | undefined> {
	const { challenge, userId, rpId } = ceremony;
	if (challenge === undefined || userId === undefined || rpId === undefined)
		return undefined;
	const party = relyingPartyOf(bucket);
	const held = await getPasskeyStore().listOf(bucket._id, user._id);
	return addOptions({
		rpId,
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

/* Why an add did not store a passkey, each a sentence the page shows. */
export type AddRefused =
	| 'expired'
	| 'no_user_verification'
	| 'exists'
	| 'full'
	| 'unavailable'
	| 'failed';

/*
 * Completes an add: spends the session's ceremony, checks again everything that may have changed since it was prepared
 * (the project, the person, their passkey identity, the project's address), verifies the device's answer against the
 * ceremony's one origin, RP ID and challenge with the person verified, then records, stores, and mails "added" with
 * its "This wasn't me" link. The session that added it is left exactly as it was.
 */
export async function completeAdd(
	bucket: UserBucket,
	user: User,
	session: PageSession,
	credential: string,
	request: Request
): Promise<{ ok: true } | { ok: false; reason: AddRefused }> {
	const ceremony = await takeCeremony(
		ceremonyId('add', session.uid),
		session.holder
	);
	if (
		ceremony?.purpose !== 'add' ||
		ceremony.accountId !== user._id ||
		ceremony.bucketId !== bucket._id ||
		ceremony.challenge === undefined ||
		ceremony.rpId === undefined ||
		ceremony.origin === undefined
	) {
		return { ok: false, reason: 'expired' };
	}
	const store = getPasskeyStore();
	const availability = await addAvailability(
		bucket,
		user,
		await store.countOf(bucket._id, user._id)
	);
	if (availability !== 'ready') {
		return {
			ok: false,
			reason: availability === 'full' ? 'full' : 'unavailable'
		};
	}
	/*
	 * The account must still hold the identity the options named (research R6), and the project must still be at the
	 * address the ceremony was made for: a passkey stored under another handle or for an old site could never sign in.
	 */
	const party = relyingPartyOf(bucket);
	if (
		ceremony.userId === undefined ||
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
		challenge: ceremony.challenge
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
		createdVia: ceremony.proof,
		createdOn,
		notMe: { digest: digestOf(secret), exp: epochTime() + NOT_ME_SECONDS }
	};
	/* Recorded before the write, as the person's other acts on this page are; the entry names no credential. */
	await recordEndUserAudit(bucket._id, user._id, 'enduser.passkey.add', {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
	if ((await store.create(record)) === 'exists') {
		return { ok: false, reason: 'exists' };
	}
	await notifyPasskey(bucket, user, {
		kind: 'added',
		madeOn: createdOn,
		at: record.createdAt.getTime(),
		disownUrl: `${accountPageBase(bucket)}${routeNames.account_passkey_disown}?token=${record._id}.${secret}${notMeProject(bucket)}`
	});
	return { ok: true };
}

/* One of this person's passkeys in this project, by its record id, or none: never another person's. */
export async function ownPasskey(
	bucket: UserBucket,
	user: User,
	id: string | undefined
): Promise<Passkey | undefined> {
	if (!id) return undefined;
	const passkey = await getPasskeyStore().find(bucket._id, id);
	return passkey?.accountId === user._id ? passkey : undefined;
}

/*
 * Whether a passkey signs in here now: the project accepts passkeys, it was made for the project's current site, and
 * it was never refused as a possible copy. A passkey that does not is still listed, and can always be removed.
 */
export function passkeyWorks(passkey: Passkey, bucket: UserBucket): boolean {
	return (
		passkeysAccepted(bucket) &&
		passkey.copiedAt === undefined &&
		passkey.rpId === relyingPartyOf(bucket).rpId
	);
}

/*
 * The last-way-in rule (data-model.md, FR-029): removing a working passkey is refused when the person would be left
 * with no way into the project. A way is a password while the project's password sign-in is open, a link to a provider
 * the project offers, or another passkey that works. Removing a passkey that does not work removes no way in.
 */
export async function isLastWayIn(
	bucket: UserBucket,
	user: User,
	passkey: Passkey
): Promise<boolean> {
	if (!passkeyWorks(passkey, bucket)) return false;
	if (bucket.passwordLogin && user.passwordSet !== false) return false;
	const offered = new Set(
		bucket.federation
			.filter((provider) => provider.enabled)
			.map((provider) => provider.id)
	);
	if ((user.federated ?? []).some((link) => offered.has(link.providerId)))
		return false;
	const others = await getPasskeyStore().listOf(bucket._id, user._id);
	return !others.some(
		(other) => other._id !== passkey._id && passkeyWorks(other, bucket)
	);
}

/*
 * A name the person typed, as it is stored (research R18): trimmed, 1–64 characters, no control characters. Answers
 * undefined for a name that is none of these, which the page refuses rather than shortens.
 */
export function passkeyNameOf(raw: string | undefined): string | undefined {
	const name = (raw ?? '').trim();
	if (name.length === 0 || name.length > NAME_MAX) return undefined;
	// eslint-disable-next-line no-control-regex -- control characters are exactly what a name may not carry
	if (/[\u0000-\u001f\u007f-\u009f]/.test(name)) return undefined;
	return name;
}

/* Renames one of the person's passkeys: their own label, so neither mailed about nor audited (data-model "Audit"). */
export async function renamePasskey(
	bucket: UserBucket,
	user: User,
	id: string | undefined,
	raw: string | undefined
): Promise<'renamed' | 'invalid' | 'gone'> {
	const passkey = await ownPasskey(bucket, user, id);
	if (!passkey) return 'gone';
	const name = passkeyNameOf(raw);
	if (name === undefined) return 'invalid';
	return (await getPasskeyStore().rename(
		bucket._id,
		user._id,
		passkey._id,
		name
	))
		? 'renamed'
		: 'gone';
}

/*
 * Prepares the removal a mailed link proved (research R14, R15): for this browser session and this passkey only, for
 * five minutes, replacing the session's earlier removal.
 */
export async function prepareRemove(
	bucket: UserBucket,
	user: User,
	session: PageSession,
	passkeyId: string
): Promise<void> {
	await prepareCeremony(ceremonyId('remove', session.uid), {
		accountId: user._id,
		bucketId: bucket._id,
		holder: session.holder,
		purpose: 'remove',
		proof: 'password_mail',
		passkeyId
	});
}

/* Whether this browser session holds a live removal, proved by a mailed link, for this passkey. */
export async function liveRemove(
	user: User,
	bucket: UserBucket,
	session: PageSession,
	passkeyId: string
): Promise<boolean> {
	const ceremony = await liveCeremony(ceremonyId('remove', session.uid));
	return (
		ceremony?.purpose === 'remove' &&
		ceremony.holder === session.holder &&
		ceremony.accountId === user._id &&
		ceremony.bucketId === bucket._id &&
		ceremony.passkeyId === passkeyId
	);
}

export type RemoveRefused = 'gone' | 'last' | 'expired';

/*
 * Removes one of the person's passkeys (FR-028–FR-030): theirs, not the last way in, and proved either by a strong
 * recent sign-in in this browser (`strong`) or by the removal a mailed link prepared for this passkey in this browser,
 * which the act spends. Recorded before the write, then mailed about; it stops signing in at once.
 */
export async function completeRemove(
	bucket: UserBucket,
	user: User,
	session: PageSession,
	passkeyId: string | undefined,
	strong: boolean
): Promise<{ ok: true } | { ok: false; reason: RemoveRefused }> {
	const passkey = await ownPasskey(bucket, user, passkeyId);
	if (!passkey) return { ok: false, reason: 'gone' };
	if (await isLastWayIn(bucket, user, passkey))
		return { ok: false, reason: 'last' };
	if (!strong) {
		if (!(await liveRemove(user, bucket, session, passkey._id)))
			return { ok: false, reason: 'expired' };
		const spent = await takeCeremony(
			ceremonyId('remove', session.uid),
			session.holder
		);
		if (spent?.passkeyId !== passkey._id)
			return { ok: false, reason: 'expired' };
	}
	await recordEndUserAudit(bucket._id, user._id, 'enduser.passkey.remove', {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
	if (!(await getPasskeyStore().remove(bucket._id, user._id, passkey._id))) {
		return { ok: false, reason: 'gone' };
	}
	await notifyPasskey(bucket, user, {
		kind: 'removed',
		madeOn: passkey.createdOn,
		createdAt: new Date(passkey.createdAt).getTime()
	});
	return { ok: true };
}

/*
 * A project with no address of its own serves its page at the root, which the default project's address names, so its
 * "This wasn't me" link names the project as well; every other project's link is named by its address alone.
 */
function notMeProject(bucket: RequestBucket): string {
	return addressOf(bucket).kind === 'unaddressed'
		? `&project=${encodeURIComponent(bucket._id)}`
		: '';
}

/*
 * The project a "This wasn't me" link acts in: the one its address names, or one the link names that has no address of
 * its own and so shares that page address (the root's). Never a project with an address of its own named from another
 * address, never the administrators' (served at the root, not unaddressed), never one being deleted.
 */
export async function notMeBucketId(
	addressed: RequestBucket,
	project: string | undefined
): Promise<string | undefined> {
	if (!project || project === addressed._id) return addressed._id;
	const named = await getBucketStore().find(project);
	if (
		!named ||
		isScheduledForDeletion(named) ||
		addressOf(named).kind !== 'unaddressed' ||
		accountPageBase(named) !== accountPageBase(addressed)
	) {
		return undefined;
	}
	return named._id;
}

/*
 * The passkey a "This wasn't me" token names (research R16), while its link is live: `<record id>.<secret>`, looked up
 * only among the passkeys of the project `notMeBucketId` gave for the address the link was opened at, so it acts
 * nowhere else. Read without spending it.
 */
export async function notMePasskey(
	bucketId: string,
	token: string
): Promise<{ passkey: Passkey; digest: string } | undefined> {
	const dot = token.indexOf('.');
	if (dot <= 0 || dot === token.length - 1) return undefined;
	const id = token.slice(0, dot);
	const digest = digestOf(token.slice(dot + 1));
	const passkey = await getPasskeyStore().find(bucketId, id);
	if (
		!passkey?.notMe ||
		passkey.notMe.digest !== digest ||
		passkey.notMe.exp <= epochTime()
	) {
		return undefined;
	}
	return { passkey, digest };
}
