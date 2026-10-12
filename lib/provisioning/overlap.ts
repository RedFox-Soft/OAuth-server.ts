import type {
	CredentialSlot,
	PreviousCredential,
	ProvisioningConnection
} from '../adapters/types.js';

/*
 * When a replaced client secret or static token stops working by itself (specs/088 R3) — the one place the
 * rule is written. The synthesized client, the SCIM principal and the connection view all ask here, so the
 * token endpoint, a SCIM request and the console can never disagree about whether a previous value is live.
 *
 * Live while all three hold:
 *   - less than 24 hours have passed since the replacement;
 *   - its own expiry (a static token's) has not passed;
 *   - it is not the case that the new value has been used and an hour has passed since the later of the
 *     previous value's last use and the new value's first use.
 *
 * The new value's *first* use, not its last: a directory uses the new value continuously, so a rule on its
 * last use would never fire. And the quiet hour, not the first use alone, because Entra's Test Connection and
 * Okta's Test Connector Configuration use the new value before the administrator saves it — an
 * administrator who tested and cancelled would otherwise lose the value the directory still runs on.
 *
 * Computed on every read rather than swept: the connections area is never reaped, and a lazy check is exact.
 */

export const OVERLAP_MAX_MS = 24 * 60 * 60 * 1000;
export const OVERLAP_QUIET_MS = 60 * 60 * 1000;

/* The previous value's last use is written at most this often, so the quiet hour is exact to a minute. */
export const PREVIOUS_USE_RESOLUTION_MS = 60_000;

export interface PreviousState {
	live: boolean;
	/* The latest it can end: 24 hours after the replacement, or its own expiry if sooner. */
	endsAt: Date;
	/* The directory used the previous value after it first used the new one, and it still works. */
	stillUsedByDirectory: boolean;
}

export function previousOf(
	connection: ProvisioningConnection,
	slot: CredentialSlot
): PreviousCredential | undefined {
	return slot === 'secret'
		? connection.previousSecret
		: connection.previousStaticToken;
}

/* The current value's first use, or undefined while it has none — or while the slot's current value is not one that overlaps. */
export function currentFirstUse(
	connection: ProvisioningConnection,
	slot: CredentialSlot
): Date | undefined {
	if (slot === 'secret') {
		return connection.oauthCredential?.kind === 'secret'
			? connection.oauthCredential.firstUsedAt
			: undefined;
	}
	return connection.staticTokenDigest
		? connection.staticTokenFirstUsedAt
		: undefined;
}

export function latestEndOf(previous: PreviousCredential): Date {
	const cap = previous.replacedAt.getTime() + OVERLAP_MAX_MS;
	const expiry = previous.expiresAt?.getTime() ?? Infinity;
	return new Date(Math.min(cap, expiry));
}

/* Null when the slot holds no previous value at all. */
export function previousState(
	connection: ProvisioningConnection,
	slot: CredentialSlot,
	now: Date = new Date()
): PreviousState | null {
	const previous = previousOf(connection, slot);
	if (!previous) return null;
	const at = now.getTime();
	const endsAt = latestEndOf(previous);
	const firstUse = currentFirstUse(connection, slot);

	const quietEnded =
		firstUse !== undefined &&
		at >=
			Math.max(
				(previous.lastUsedAt ?? previous.replacedAt).getTime(),
				firstUse.getTime()
			) +
				OVERLAP_QUIET_MS;
	const live = at < endsAt.getTime() && !quietEnded;

	return {
		live,
		endsAt,
		stillUsedByDirectory:
			live &&
			firstUse !== undefined &&
			previous.lastUsedAt !== undefined &&
			previous.lastUsedAt.getTime() > firstUse.getTime()
	};
}

export function isPreviousLive(
	connection: ProvisioningConnection,
	slot: CredentialSlot,
	now: Date = new Date()
): boolean {
	return previousState(connection, slot, now)?.live === true;
}

/*
 * What marks a client-credentials token with the secret that obtained it (specs/088 R2): the first 16 hex
 * characters of that secret's digest. A prefix of a 256-bit random value's digest reveals nothing usable,
 * and it is never shown in any read.
 */
export function credentialRefOf(digest: string): string {
	return digest.slice(0, 16);
}

/* Whether this use of the previous value should be written, given when it was last written. */
export function previousUseDue(
	previous: PreviousCredential,
	now: Date
): boolean {
	return (
		!previous.lastUsedAt ||
		now.getTime() - previous.lastUsedAt.getTime() >= PREVIOUS_USE_RESOLUTION_MS
	);
}
