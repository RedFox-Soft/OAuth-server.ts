import { getPasskeyStore, getUserStore } from '../adapters/index.js';
import type { User } from '../adapters/types.js';

/*
 * The passkey offer's state on the person (specs/141 research R4), written only here. A leaf module beside the
 * end-user service, which re-exports it, because the password reset needs it and the service imports the reset. The person's own acts, so no
 * audit record. A read and a write of one small object: two sign-ins racing may count one showing where there were two,
 * which only shortens nothing (the pause runs from the later write either way).
 */
async function writeOffer(
	bucketId: string,
	accountId: string,
	change: (
		current: NonNullable<User['passkeyOffer']>
	) => NonNullable<User['passkeyOffer']> | undefined
): Promise<void> {
	const user = await getUserStore(bucketId).find(accountId);
	if (!user) return;
	const next = change(user.passkeyOffer ?? { shown: 0 });
	if (next === undefined) return;
	await getUserStore(bucketId).update(accountId, { passkeyOffer: next });
}

/* The offer was shown: one more showing, and the 30-day pause runs from now. */
export async function noteOfferShown(
	bucketId: string,
	accountId: string,
	at: Date = new Date()
): Promise<void> {
	await writeOffer(bucketId, accountId, (current) => ({
		...current,
		shown: current.shown + 1,
		lastShownAt: at
	}));
}

/* "Don't ask again": no offer for this person in this project, ever; their own page still adds passkeys. */
export async function declineOffers(
	bucketId: string,
	accountId: string
): Promise<void> {
	await writeOffer(bucketId, accountId, (current) => ({
		...current,
		never: true
	}));
}

/* "This wasn't me": whoever knows the password is not offered a passkey again until the password is reset (FR-014). */
export async function holdOffers(
	bucketId: string,
	accountId: string
): Promise<void> {
	await writeOffer(bucketId, accountId, (current) =>
		current.held ? undefined : { ...current, held: true }
	);
}

/* A password reset: the owner is back, and the offer may be made again. */
export async function releaseOffers(
	bucketId: string,
	accountId: string
): Promise<void> {
	await writeOffer(bucketId, accountId, (current) => {
		if (!current.held) return undefined;
		const { held: _held, ...rest } = current;
		return rest;
	});
}

/*
 * Every conditional passkey of the person (specs/141 FR-013): each rested on the password alone, so whatever ends trust
 * in that password ends them too. At most twenty records, so a list and one removal each. Answers how many went.
 */
export async function removeConditionalPasskeys(
	bucketId: string,
	accountId: string
): Promise<number> {
	const store = getPasskeyStore();
	let removed = 0;
	for (const passkey of await store.listOf(bucketId, accountId)) {
		if (
			passkey.conditional === true &&
			(await store.remove(bucketId, accountId, passkey._id))
		) {
			removed += 1;
		}
	}
	return removed;
}

/* How many conditional passkeys the person holds, for an audit entry written before they are removed. */
export async function conditionalPasskeysOf(
	bucketId: string,
	accountId: string
): Promise<number> {
	const held = await getPasskeyStore().listOf(bucketId, accountId);
	return held.filter((passkey) => passkey.conditional === true).length;
}
