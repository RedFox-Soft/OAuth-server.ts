import crypto from 'node:crypto';

import { checkedAdapter } from '../adapters/index.js';
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
 * Records are keyed by their **holder** — the interaction uid at sign-in, `account:<session uid>` on the person's own
 * page (specs/126) — which decides three things at once. There is no
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
 * The secret on offer for this holder — created on the first call, and the *same one* on every
 * later call until it is confirmed or expires.
 */
export async function offer(
	holder: string,
	accountId: string,
	bucketId: string,
	{ email, label }: { email: string; label: string },
	extras: { replacing?: number } = {}
): Promise<Offer> {
	const existing = await enrollments().find(holder);

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
			holder,
			{
				accountId,
				bucketId,
				secret,
				exp,
				...(extras.replacing !== undefined
					? { replacing: extras.replacing }
					: {})
			},
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

/* What a code proved: the secret it was made from, and the step it matched, which the enrolment spends. */
export interface Proved {
	secret: string;
	step: number;
}

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
 *
 * `holder` is where the offer lives: the interaction uid at sign-in, `account:<session uid>` on the person's own page
 * (specs/126). The write is the caller's, through lib/end_users/service.ts, because what an enrolment also records —
 * how it was set up, an audit entry, a confirmed address — depends on where it happened. `enrol` answers false when
 * the account is gone; it receives the step so the code that completed the enrolment cannot also sign in.
 */
export async function confirm(
	holder: string,
	accountId: string,
	bucketId: string,
	code: string,
	enrol: (proved: Proved) => Promise<boolean>
): Promise<ConfirmOutcome> {
	const pending = await enrollments().find(holder);
	if (!pending || pending.exp <= epochTime()) {
		return { ok: false, reason: 'expired' };
	}
	if (!ownedBy(pending, accountId, bucketId)) {
		await enrollments().destroy(holder);
		return { ok: false, reason: 'expired' };
	}

	const step = verifyAt(decodeBase32(pending.secret), code, epochTime());
	if (step === null) {
		return { ok: false, reason: 'invalid' };
	}

	/*
	 * The pending record goes either way. When the account is gone there is nothing left to enrol into, so leaving it
	 * would only keep a live secret addressed to a dead account until its TTL caught up.
	 */
	const enrolled = await enrol({ secret: pending.secret, step });
	await enrollments().destroy(holder);
	return enrolled ? { ok: true } : { ok: false, reason: 'gone' };
}

/* Ends an offer without enrolling: a new start, or a page that is no longer allowed to finish it. */
export async function dropOffer(holder: string): Promise<void> {
	await enrollments().destroy(holder);
}

/* The offer waiting for this holder, when it belongs to this account: what a page needs to finish it. */
export async function waitingOffer(
	holder: string,
	accountId: string,
	bucketId: string
): Promise<{ replacing?: number; attempts: number } | undefined> {
	const pending = await enrollments().find(holder);
	if (
		!pending ||
		pending.exp <= epochTime() ||
		!ownedBy(pending, accountId, bucketId)
	) {
		return undefined;
	}
	return {
		...(pending.replacing !== undefined
			? { replacing: pending.replacing }
			: {}),
		attempts: pending.attempts ?? 0
	};
}

/*
 * One more wrong code against the offer on the person's page, answering how many there have been. The offer goes at
 * the fifth, as an enrolment at sign-in ends: a new start costs a mailed link, which has limits of its own.
 */
export async function noteWrongCode(holder: string): Promise<number> {
	const pending = await enrollments().find(holder);
	if (!pending) return Number.POSITIVE_INFINITY;
	const attempts = (pending.attempts ?? 0) + 1;
	const remaining = pending.exp - epochTime();
	if (remaining <= 0) return Number.POSITIVE_INFINITY;
	await enrollments().upsert(holder, { ...pending, attempts }, remaining);
	return attempts;
}
