import crypto from 'node:crypto';

import { checkedAdapter, getUserStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { decodeBase32, encodeBase32 } from './base32.js';
import { verifyAt } from './code.js';
import {
	DIGITS,
	ENROLLMENT_TTL_SECONDS,
	SECRET_BYTES,
	STEP_SECONDS
} from './consts.js';
import { TotpEnrollmentPayload } from './types.js';

/*
 * The lifecycle of a secret that has been offered but not yet proved.
 *
 * Records are keyed by the **interaction uid**, which decides three things at once. There is no
 * enrolment handle to put in a hidden form field, so none to leak or to guess. An enrolment can only be
 * completed from inside the interaction that started it. And a reload or a wrong code re-reads the same
 * record, so the same secret stays on screen — a fresh one per request would mean a person who mistyped
 * a digit has to delete and re-add the entry in their app.
 *
 * The uid is not the whole ownership check, though. The password step can be submitted again inside
 * one interaction, changing whose sign-in it is, so the record also names its account and bucket and
 * both `offer` and `confirm` compare them with the sign-in's own.
 *
 * Nothing here writes to the account until a code proves possession, so an abandoned enrolment leaves
 * the account exactly as it was.
 */

function enrollments() {
	return checkedAdapter('TotpEnrollment', TotpEnrollmentPayload);
}

/*
 * The URI the QR encodes. The label is the bucket's name — the same value the verification mail uses to
 * say who is asking — so an authenticator app lists the entry under something the person recognises.
 *
 * `algorithm`, `digits` and `period` are stated even though several widely deployed apps ignore them
 * and assume exactly these values: the apps that do read them are then correct, and the ones that do
 * not are correct by coincidence. Every component is encoded, because the label comes from operator
 * input and an account is an email address.
 */
export function otpauthUriFor(
	email: string,
	label: string,
	secret: string
): string {
	const account = `${encodeURIComponent(label)}:${encodeURIComponent(email)}`;
	const query = new URLSearchParams({
		secret,
		issuer: label,
		algorithm: 'SHA1',
		digits: String(DIGITS),
		period: String(STEP_SECONDS)
	});
	return `otpauth://totp/${account}?${query.toString()}`;
}

/* Grouped in fours: this is read off a screen and retyped, and an unbroken 32-character run is not. */
export function groupSecret(secret: string): string {
	return (secret.match(/.{1,4}/g) ?? []).join(' ');
}

export interface Offer {
	secret: string;
	otpauthUri: string;
	secretText: string;
}

function ownedBy(
	pending: { accountId: string; bucketId: string },
	accountId: string,
	bucketId: string
): boolean {
	return pending.accountId === accountId && pending.bucketId === bucketId;
}

/*
 * The secret on offer for this interaction — created on the first call, and the *same one* on every
 * later call until it is confirmed or expires.
 */
export async function offer(
	uid: string,
	accountId: string,
	bucketId: string,
	{ email, label }: { email: string; label: string }
): Promise<Offer> {
	const existing = await enrollments().find(uid);

	// Compared rather than left to the store: MongoDB's TTL monitor deletes lazily, so an expired
	// record can still be found for a while — the departure lib/password_reset/challenge.ts makes for
	// the same reason, and it matters more here because this secret becomes a standing credential.
	//
	// And re-offered only to the account it was minted for. The password step can be submitted again
	// inside the same interaction, so the uid alone does not say whose secret this is.
	const live =
		existing &&
		existing.exp > epochTime() &&
		ownedBy(existing, accountId, bucketId)
			? existing
			: undefined;

	const secret = live?.secret ?? encodeBase32(crypto.randomBytes(SECRET_BYTES));

	if (!live) {
		const exp = epochTime() + ENROLLMENT_TTL_SECONDS;
		await enrollments().upsert(
			uid,
			{ accountId, bucketId, secret, exp },
			ENROLLMENT_TTL_SECONDS
		);
	}

	return {
		secret,
		otpauthUri: otpauthUriFor(email, label, secret),
		secretText: groupSecret(secret)
	};
}

export type ConfirmOutcome =
	{ ok: true } | { ok: false; reason: 'expired' | 'invalid' | 'gone' };

/*
 * Turn a proved secret into the account's enrolment.
 *
 * The three refusals are distinguished for the caller alone, because each needs a different next
 * page: `expired` routes to a fresh secret, `invalid` re-renders the page already on screen, and
 * `gone` sends them back to the login door. Only the first two reach a person, and they reach them
 * as the same words.
 *
 * `accountId` and `bucketId` are the sign-in's, not the offer's: the caller completes the sign-in of
 * the account the interaction now names, so a secret offered to anyone else is spent and refused as
 * expired. Otherwise a code proved for one account enrolled that account and signed in another.
 */
export async function confirm(
	uid: string,
	accountId: string,
	bucketId: string,
	code: string
): Promise<ConfirmOutcome> {
	const pending = await enrollments().find(uid);
	if (!pending || pending.exp <= epochTime()) {
		return { ok: false, reason: 'expired' };
	}
	if (!ownedBy(pending, accountId, bucketId)) {
		await enrollments().destroy(uid);
		return { ok: false, reason: 'expired' };
	}

	const step = verifyAt(decodeBase32(pending.secret), code, epochTime());
	if (step === null) {
		return { ok: false, reason: 'invalid' };
	}

	/*
	 * `lastStep` starts at the step just proved, not at zero: the code that completed the enrolment is
	 * spent, and a person who submits it once more within the same 30 seconds — a double-submitted form,
	 * or someone who watched them type it — must not be able to use it to sign in.
	 */
	const enrolled = await getUserStore(pending.bucketId).update(
		pending.accountId,
		{
			totp: { secret: pending.secret, enrolledAt: new Date(), lastStep: step }
		}
	);
	/*
	 * The write is the enrolment; reporting success without it would hand the caller a completed
	 * second factor for an account that holds none — and, because the caller then writes
	 * `result.login`, sign a person in as an account that no longer exists. `update` returns null for
	 * exactly one reason: the row is gone, deleted between the offer and this confirmation.
	 *
	 * The pending record goes either way. There is nothing left to enrol into, so leaving it would
	 * only keep a live secret addressed to a dead account until its TTL caught up.
	 */
	if (!enrolled) {
		await enrollments().destroy(uid);
		return { ok: false, reason: 'gone' };
	}

	await enrollments().destroy(uid);
	return { ok: true };
}
