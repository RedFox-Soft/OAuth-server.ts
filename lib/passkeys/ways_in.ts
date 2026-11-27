import { getPasskeyStore, getUserStore } from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import { selfServiceResetAllowed } from '../password_reset/eligibility.js';
import { passkeysAccepted } from './accepted.js';
import { relyingPartyOf } from './relying_party.js';

/*
 * The one rule for how a person can get into a project besides a passkey, and what the console may say about a
 * passkey (specs/140 research R5, R9). The person's own removal, the turn-off preview, the address change preview and
 * the console's revocation dialog all read it, so none of them can call someone locked out whom another calls fine.
 */

/*
 * Why a passkey does or does not sign in here, judged in this order: one refused as copied never works again, one made
 * for another site never works at this address, and the others work exactly while the project accepts passkeys.
 */
export type PasskeyState = 'copied' | 'old_address' | 'off' | 'works';

export function passkeyState(
	passkey: Passkey,
	bucket: UserBucket
): PasskeyState {
	if (passkey.copiedAt !== undefined) return 'copied';
	if (passkey.rpId !== relyingPartyOf(bucket).rpId) return 'old_address';
	if (!passkeysAccepted(bucket)) return 'off';
	return 'works';
}

/*
 * The people of a project named by id, a hundred reads at a time: a project where every person holds a passkey must
 * not open fifty thousand reads at once (SC-007). People since deleted are left out.
 */
export async function usersOf(
	bucketId: string,
	ids: readonly string[]
): Promise<User[]> {
	const store = getUserStore(bucketId);
	const found: User[] = [];
	for (let start = 0; start < ids.length; start += 100) {
		const batch = await Promise.all(
			ids.slice(start, start + 100).map((id) => store.find(id))
		);
		for (const user of batch) if (user) found.push(user);
	}
	return found;
}

/* The providers this project offers that the person is linked to, by their shown names. */
function linkedProviders(bucket: UserBucket, user: User): string[] {
	const linked = new Set((user.federated ?? []).map((link) => link.providerId));
	return bucket.federation
		.filter((provider) => provider.enabled && linked.has(provider.id))
		.map((provider) => provider.displayName);
}

/*
 * Another way in: a password while the project's password door is open (`passwordsOpen`, so a preview can ask about
 * the door as a change would leave it), or a link to a provider the project offers. A passkey is never one; callers
 * count working passkeys themselves.
 */
export function otherWayIn(
	bucket: UserBucket,
	user: User,
	{ passwordsOpen }: { passwordsOpen: boolean }
): boolean {
	return (
		(passwordsOpen && user.passwordSet !== false) ||
		linkedProviders(bucket, user).length > 0
	);
}

/*
 * A passkey as the console and an agent see it: an explicit projection, so its credential id, public key, counter,
 * transports, AAGUID, RP ID and "This wasn't me" state can never leave through a field added later.
 */
export interface PasskeyView {
	id: string;
	name?: string;
	createdOn: Passkey['createdOn'];
	synced: boolean;
	createdAt: string;
	createdVia: Passkey['createdVia'];
	lastUsedAt?: string;
	state: PasskeyState;
	/* False for a passkey made after a password alone and not yet confirmed: it signs in as that password (specs/141). */
	confirmed: boolean;
}

function isoOf(value: Date | string): string {
	return new Date(value).toISOString();
}

export function passkeyView(passkey: Passkey, bucket: UserBucket): PasskeyView {
	return {
		id: passkey._id,
		...(passkey.name === undefined ? {} : { name: passkey.name }),
		createdOn: {
			browser: passkey.createdOn.browser,
			system: passkey.createdOn.system
		},
		synced: passkey.backedUp,
		createdAt: isoOf(passkey.createdAt),
		createdVia: passkey.createdVia,
		...(passkey.lastUsedAt === undefined
			? {}
			: { lastUsedAt: isoOf(passkey.lastUsedAt) }),
		state: passkeyState(passkey, bucket),
		confirmed: passkey.conditional !== true
	};
}

/*
 * How a person left with no way in gets back (contracts/console-and-mail.md): `self` when they can choose a password
 * with "Forgot your password?" (the project offers it, mail works and their address is proven, since a reset of an
 * unproven account starts it over), `admin` when an administrator can set one that the password door then accepts,
 * `none` otherwise.
 */
export type Restore = 'self' | 'admin' | 'none';

export interface PasskeysOfPerson {
	passkeys: PasskeyView[];
	ways: { password: boolean; providers: string[] };
	restore: Restore;
	mailable: boolean;
}

export async function passkeysOfPerson(
	bucket: UserBucket,
	user: User,
	held: readonly Passkey[]
): Promise<PasskeysOfPerson> {
	const onlyPasskeyReaches =
		bucket._id === ADMIN_BUCKET_ID && bucket.consolePasskeyRequired === true;
	const passwordsOpen = !onlyPasskeyReaches && bucket.passwordLogin;
	// As notifyPasskey decides it: a proven, non-empty address.
	const mailable = user.verified && user.email !== '';
	const restore: Restore = onlyPasskeyReaches
		? 'none'
		: selfServiceResetAllowed(bucket._id, bucket) &&
			  mailable &&
			  (await mailDeliveryConfigured())
			? 'self'
			: user.provisionedBy === undefined && passwordsOpen
				? 'admin'
				: 'none';
	return {
		passkeys: [...held]
			.sort(
				(a, b) =>
					new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
			)
			.map((passkey) => passkeyView(passkey, bucket)),
		ways: {
			password: passwordsOpen && user.passwordSet !== false,
			providers: onlyPasskeyReaches ? [] : linkedProviders(bucket, user)
		},
		restore,
		mailable
	};
}

/*
 * What an address change does to a project's passkeys (specs/140 research R7), when it gives them another RP ID: the
 * passkeys of the current one, not refused as copied, stop working for good, whether or not the project accepts
 * passkeys right now. Their holders are split by whether they keep another way in after the move: a password while
 * the door is open, a link to a provider the project offers, or a passkey already made for the new RP ID (a project
 * moving back). Those without are named by address, the first twenty, so the operator can reach them first.
 */
export interface PasskeysLostByMove {
	passkeys: number;
	people: number;
	withOtherWay: number;
	withoutOtherWay: number;
	without: string[];
	more: number;
}

const NAMED = 20;

export async function passkeysLostByMove(
	bucket: UserBucket,
	nextRpId: string
): Promise<PasskeysLostByMove | null> {
	const current = relyingPartyOf(bucket).rpId;
	if (current === nextRpId) return null;
	const store = getPasskeyStore();
	const holders = await store.holdingIn(bucket._id, current);
	if (holders.length === 0) return null;
	const kept = new Set(
		(await store.holdingIn(bucket._id, nextRpId)).map(
			(holder) => holder.accountId
		)
	);
	const people = await usersOf(
		bucket._id,
		holders.map((holder) => holder.accountId)
	);
	const locked = people
		.filter(
			(user) =>
				!kept.has(user._id) &&
				!otherWayIn(bucket, user, { passwordsOpen: bucket.passwordLogin })
		)
		.map((user) => user.email || user._id)
		.sort();
	return {
		passkeys: holders.reduce((sum, holder) => sum + holder.passkeys, 0),
		people: holders.length,
		withOtherWay: holders.length - locked.length,
		withoutOtherWay: locked.length,
		without: locked.slice(0, NAMED),
		more: Math.max(0, locked.length - NAMED)
	};
}
