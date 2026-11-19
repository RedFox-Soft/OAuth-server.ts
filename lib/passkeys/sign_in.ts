import { randomBytes } from 'node:crypto';

import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';

import { getPasskeyStore, getUserStore } from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { isAccountPageClient } from '../account_page/client.js';
import { configuration } from '../configs/application.js';
import epochTime from '../helpers/epoch_time.js';
import type { Interaction } from '../models/interaction.js';
import { noteSignInRefused } from '../person_activity/record.js';
import { passkeysAccepted } from './accepted.js';
import { readAssertion, signInOptions, verifySignIn } from './ceremony.js';
import { CEREMONY_SECONDS } from './consts.js';
import { admitPasskeyAttempt, countPasskeyFailure } from './limits.js';
import { relyingPartyOf } from './relying_party.js';
import { hasOwnOrigin } from '../configs/issuer.js';

/*
 * Signing in with a passkey on the project's sign-in page (specs/139 contracts/sign-in.md): the offer every render of
 * the page carries, and the door that judges what the browser posts back. The door's account gates and its success
 * are the password door's own (lib/interactions/index.ts); what is decided here is everything about the passkey.
 */

/*
 * What the page hands its script: the request options, and whether the page has a "Remember me" checkbox the result
 * must follow. Without one (no password form) the sign-in is remembered, as a provider sign-in is.
 */
export interface PasskeyOffer {
	options: PublicKeyCredentialRequestOptionsJSON;
	remember: boolean;
}

/*
 * A re-authentication the person's own page asked for an act that needs a fresh password or a fresh code (research
 * R13): two-step verification's start, replacement and removal. Its request names only the password context in
 * `acr_values`, and only the page's own client sends it, so no relying party's request changes meaning. A passkey
 * offered there would sign the person in without the proof the act waits for, and bring them back to be asked again.
 */
export function passwordOnlyReauthentication(
	interaction: Interaction
): boolean {
	const params = interaction.payload.params;
	if (!isAccountPageClient(params?.client_id)) return false;
	const asked =
		typeof params?.acr_values === 'string'
			? params.acr_values.split(' ').filter(Boolean)
			: [];
	return (
		asked.length > 0 &&
		asked.every((value) => value === configuration.acrMap.password)
	);
}

/*
 * The passkey offer of one render of the sign-in page, or none where the project does not accept passkeys or the
 * request is a password-only re-authentication. Writes a fresh challenge onto the interaction and saves it, replacing
 * the one an earlier render (or another tab) wrote: one challenge per interaction (research R7).
 */
export async function offerFor(
	interaction: Interaction,
	bucket: UserBucket,
	page: { remember: boolean }
): Promise<PasskeyOffer | undefined> {
	if (!passkeysAccepted(bucket) || passwordOnlyReauthentication(interaction))
		return undefined;
	const value = randomBytes(32).toString('base64url');
	interaction.payload.passkeyChallenge = {
		value,
		exp: epochTime() + CEREMONY_SECONDS
	};
	await interaction.persist();
	return {
		options: await signInOptions({
			rpId: relyingPartyOf(bucket).rpId,
			challenge: value
		}),
		remember: page.remember
	};
}

/*
 * What the passkey door decided, in the order of contracts/sign-in.md. `refused` is every failure about the passkey,
 * which the person reads as one sentence whatever it was (FR-008); `verified` is a passkey that proved its account,
 * which still has the account gates ahead of it.
 */
export type PasskeyAttempt =
	| { kind: 'off' }
	| { kind: 'limited'; retryAfter: number }
	| { kind: 'retry' }
	/*
	 * `unknown`: the browser may be told to forget this passkey (specs/141 research R10). Set only at a project's own
	 * site, and only for a credential no project on the instance holds for it.
	 */
	| { kind: 'refused'; unknown?: UnknownPasskey }
	/* The passkey too: a conditional one signs in as its password does (specs/141). */
	| { kind: 'verified'; user: User; passkey: Passkey };

/* A passkey a browser may be told to forget: its site and its credential id, both the browser's own already. */
export interface UnknownPasskey {
	rpId: string;
	credentialId: string;
}

/*
 * Whether a credential this project does not hold may be reported unknown (specs/141 research R10): only at a site the
 * project has to itself (a subdomain or a host of its own), where no other project's passkey can live, and only when
 * no project on the instance holds it for that site, so a project that left the address and comes back to it finds
 * its people's passkeys still in their managers. At the instance's own host, shared by the root, the path projects
 * and the administrators, never: "not this project's" says nothing about theirs.
 */
async function unknownHere(
	bucket: UserBucket,
	credentialId: string
): Promise<UnknownPasskey | undefined> {
	if (!hasOwnOrigin(bucket)) return undefined;
	const { rpId } = relyingPartyOf(bucket);
	if (await getPasskeyStore().knownAnywhere(rpId, credentialId))
		return undefined;
	return { rpId, credentialId };
}

/*
 * Judges one posted passkey for the project the sign-in belongs to (`bucket`, the interaction's `signsInto`):
 *
 * 1. the project still accepts passkeys (re-read, since the page may be older than a switch turned off);
 * 2. the caller is under its hourly bound of failures, checked before anything is looked up;
 * 3. the interaction's challenge is taken off whatever follows, so no response is judged twice against it; a missing
 *    or stale one is the page's age, not an attempt, and is neither counted nor noted;
 * 4. the passkey is looked up among this project's only, its account exists here, it was made for the project's
 *    current site and is not marked as possibly copied;
 * 5. the response verifies against exactly one origin, one RP ID and this challenge, with the person verified and the
 *    account's own user handle;
 * 6. its counter moves forward (or stays at zero on a device that never counts), and the conditional write of it wins.
 *
 * From step 4 on a failure counts against the caller, and once the passkey's account is known the person's activity
 * keeps a `passkey_refused`. Nothing about the credential, the challenge or the signature is logged or noted.
 */
export async function judgePasskey(input: {
	interaction: Interaction;
	bucket: UserBucket | null;
	credential: string;
	request: Request;
	clientId: string | undefined;
}): Promise<PasskeyAttempt> {
	const { interaction, bucket, request } = input;
	if (!bucket || !passkeysAccepted(bucket)) return { kind: 'off' };

	const admission = await admitPasskeyAttempt(request);
	if (!admission.admitted)
		return { kind: 'limited', retryAfter: admission.retryAfter };

	const challenge = interaction.payload.passkeyChallenge;
	if (challenge !== undefined) {
		delete interaction.payload.passkeyChallenge;
		await interaction.persist();
	}
	if (challenge === undefined || challenge.exp <= epochTime())
		return { kind: 'retry' };

	const refuse = async (accountId?: string): Promise<PasskeyAttempt> => {
		await countPasskeyFailure(request);
		if (accountId !== undefined) {
			noteSignInRefused({
				bucketId: bucket._id,
				accountId,
				reason: 'passkey_refused',
				clientId: input.clientId,
				method: 'passkey',
				request
			});
		}
		return { kind: 'refused' };
	};

	const response = readAssertion(input.credential);
	if (!response) return refuse();
	const store = getPasskeyStore();
	const passkey = await store.findByCredential(bucket._id, response.id);
	if (!passkey) {
		const refused = await refuse();
		const unknown = await unknownHere(bucket, response.id);
		return unknown ? { kind: 'refused', unknown } : refused;
	}
	const user = await getUserStore(bucket._id).find(passkey.accountId);
	if (!user) return refuse();
	const party = relyingPartyOf(bucket);
	/*
	 * Made for another site of this project (its address changed since), or marked after a counter went back: either
	 * way it is listed on the person's page with its mark, and refused here in the same words as a stranger's.
	 */
	if (
		passkey.rpId !== party.rpId ||
		passkey.copiedAt !== undefined ||
		user.webauthnUserId === undefined
	) {
		return refuse(user._id);
	}

	const verified = await verifySignIn(
		response,
		{ rpId: party.rpId, origin: party.origin, challenge: challenge.value },
		{
			credentialId: passkey.credentialId,
			publicKey: passkey.publicKey,
			counter: passkey.counter,
			userHandle: user.webauthnUserId
		}
	);
	if (!verified.ok) {
		/*
		 * A genuine signature with a counter that went back: another copy of this passkey has been used since (FR-015).
		 * Marked, so every later use is refused too until the person removes it and adds a new one.
		 */
		if (verified.reason === 'counter_back')
			await store.markCopied(bucket._id, passkey._id, new Date());
		return refuse(user._id);
	}
	/*
	 * Conditional on the counter still being below the new one: of two responses racing with one counter value, one
	 * wins, and the other is refused rather than letting the same use sign in twice.
	 */
	const recorded = await store.recordUse(bucket._id, passkey._id, {
		counter: verified.counter,
		backedUp: verified.backedUp,
		at: new Date()
	});
	if (!recorded) return refuse(user._id);
	return { kind: 'verified', user, passkey };
}
