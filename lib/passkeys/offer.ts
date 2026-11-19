import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';

import { getPasskeyStore } from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import constantEquals from '../helpers/constant_equals.js';
import epochTime from '../helpers/epoch_time.js';
import type { Session } from '../models/session.js';
import {
	digestOf,
	pageHolder,
	strongRecentSignIn
} from '../totp/self_service.js';
import {
	type AddRefused,
	creationOptionsFor,
	prepareCreation,
	storeAdd
} from './account.js';
import { ceremonyId, takeCeremony } from './ceremonies.js';

/*
 * The passkey offer after a sign-in with a password (specs/141 contracts/sign-in-and-offer.md), and the confirmation
 * that makes a conditional passkey full (contracts/account-page-and-mail.md). The interaction routes and the account
 * page call these; what a passkey made here is, and what may make it full, is decided here only.
 *
 * A passkey made after a password and a code is full at once. One made after a password alone is conditional: it signs
 * in as that password does (lib/consts/amr.ts), and only its mailed "Yes, this was me", opened in the browser session
 * that made it, or a confirmation after a strong sign-in makes it full (research R2, R7, R9).
 */

export type { OfferKind } from './offerable.js';
import type { OfferKind } from './offerable.js';

/*
 * The offer's ceremony for one showing: keyed by the interaction, held by the browser session the sign-in made, so the
 * passkey it makes can be confirmed in that session only. Answers the options the page hands the browser.
 */
export async function prepareOffer(
	bucket: UserBucket,
	user: User,
	holder: string,
	kind: OfferKind,
	uid: string
): Promise<PublicKeyCredentialCreationOptionsJSON | undefined> {
	const ceremony = await prepareCreation(bucket, user, {
		id: ceremonyId('offer', uid),
		holder,
		purpose: 'offer',
		proof: kind === 'full' ? 'password_code' : 'password'
	});
	return creationOptionsFor(bucket, user, ceremony);
}

/*
 * Stores what the device made at the offer. A silent answer (the browser's own creation, with no check of the person)
 * is taken only for an offer whose passkey is full at once; for a conditional one it is refused and nothing is stored
 * (research R8, FR-020). The ceremony is spent either way.
 */
export async function completeOffer(
	bucket: UserBucket,
	user: User,
	holder: string,
	uid: string,
	credential: string,
	silent: boolean,
	request: Request
): Promise<
	| { ok: true; passkey: Passkey; kind: OfferKind }
	| { ok: false; reason: AddRefused }
> {
	const ceremony = await takeCeremony(ceremonyId('offer', uid), holder);
	if (ceremony?.purpose !== 'offer') return { ok: false, reason: 'expired' };
	if (silent && ceremony.proof !== 'password_code') {
		return { ok: false, reason: 'failed' };
	}
	const stored = await storeAdd(bucket, user, ceremony, credential, request, {
		silent
	});
	if (!stored.ok) return stored;
	return {
		ok: true,
		passkey: stored.passkey,
		kind: stored.passkey.conditional === true ? 'conditional' : 'full'
	};
}

export type ConfirmOutcome = 'confirmed' | 'already' | 'cannot';

/*
 * "Yes, this was me" (contracts/account-page-and-mail.md): `<record id>.<secret>`, the person's own passkey in this
 * project, still within its 72 hours, posted in the browser session that made it. A passkey no longer conditional is
 * "already" without the secret being checked, since confirming removed it; that tells the person nothing about anyone
 * else's passkey. Recorded before the write.
 */
export async function confirmByLink(
	bucket: UserBucket,
	user: User,
	session: Session,
	token: string
): Promise<ConfirmOutcome> {
	const dot = token.indexOf('.');
	if (dot <= 0 || dot === token.length - 1) return 'cannot';
	const passkey = await getPasskeyStore().find(bucket._id, token.slice(0, dot));
	if (passkey?.accountId !== user._id) return 'cannot';
	if (passkey.conditional !== true) return 'already';
	const pending = passkey.confirm;
	if (
		!pending ||
		pending.exp <= epochTime() ||
		!constantEquals(digestOf(token.slice(dot + 1)), pending.digest) ||
		!constantEquals(digestOf(pageHolder(session)), pending.holder)
	) {
		return 'cannot';
	}
	return confirm(bucket, user, passkey);
}

/*
 * "Confirm" on the person's own page: only after a strong recent sign-in, never through a mailed link, so a link opened
 * in the owner's browser never confirms a passkey someone else made (research R9).
 */
export async function confirmOnPage(
	bucket: UserBucket,
	user: User,
	session: Session,
	id: string | undefined
): Promise<ConfirmOutcome> {
	if (!strongRecentSignIn(session) || !id) return 'cannot';
	const passkey = await getPasskeyStore().find(bucket._id, id);
	if (passkey?.accountId !== user._id) return 'cannot';
	if (passkey.conditional !== true) return 'already';
	return confirm(bucket, user, passkey);
}

async function confirm(
	bucket: UserBucket,
	user: User,
	passkey: Passkey
): Promise<ConfirmOutcome> {
	await recordEndUserAudit(bucket._id, user._id, 'enduser.passkey.confirm', {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
	return (await getPasskeyStore().confirm(bucket._id, passkey._id))
		? 'confirmed'
		: 'already';
}
