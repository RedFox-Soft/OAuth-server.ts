import crypto from 'crypto';

import { ISSUER } from '../../configs/env.js';

/*
 * The invitation secret, and the two rules that make it one.
 *
 * Modelled on `lib/password_reset/challenge.ts`, which already solved this shape: a single-use,
 * expiring secret that is mailed once and never stored. The token itself is 256 bits of uniform
 * randomness and only its digest is kept, so a database read yields nothing usable — an invitation is
 * an offer of access to everything a group owns, and a readable one would be a standing key to it.
 *
 * Unsalted SHA-256 is right here for the reason the reset challenge records: the input has no
 * structure to brute-force and nothing to rainbow-table, and a salted digest could not be derived
 * from the token alone, which is what keeps acceptance a point read rather than a scan.
 */

/* How long an invitation stands. Longer than a password reset: it is sent to somebody who may not be
 * expecting it and has to be actioned during a working day, not within the hour. Short enough that a
 * mailbox read weeks later is worthless. */
export const INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60;

export function newInvitationToken(): string {
	return crypto.randomBytes(32).toString('base64url');
}

export function invitationTokenHash(token: string): string {
	return crypto.createHash('sha256').update(token).digest('hex');
}

export function invitationUrlFor(token: string): string {
	return `${ISSUER}/admin/accept-invitation?token=${encodeURIComponent(token)}`;
}
