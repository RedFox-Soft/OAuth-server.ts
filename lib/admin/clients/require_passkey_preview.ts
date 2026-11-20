import { getPasskeyStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { passkeysAccepted } from '../../passkeys/accepted.js';
import { relyingPartyOf } from '../../passkeys/relying_party.js';
import { AdminError } from '../auth/rbac.js';
import { signInCounts } from '../buckets/sign_in_preview.js';
import { holdersOf } from './require_code_preview.js';

/*
 * What making an application require a passkey would do, counted before it is done (specs/142 contracts/admin-and-mcp),
 * in the protocol of requiring a code (require_code_preview.ts): the first call answers 409 with these, and the change
 * applies only when repeated with `confirm` and the same counts.
 *
 * "Without a confirmed passkey" counts the people of the project who hold no full passkey for its current site: a
 * conditional one is worth a password until it is confirmed, and one made for another address no longer works here.
 */

export interface RequirePasskeyPreview {
	consequences: string[];
	expect: { withoutPasskey: number; providerOnly: number; holders: number };
	changes: ['requirePasskeyOn'];
}

function people(n: number, one: string, many: string): string {
	return n === 1 ? `1 person ${one}` : `${n} people ${many}`;
}

/*
 * Refuses the requirement in a project that does not accept passkeys (which includes the administrators' project):
 * nobody could meet it there. Turning it off, or leaving it as it is, is never refused.
 */
export function assertPasskeysAccepted(
	bucket: UserBucket,
	turnsOn: boolean | undefined
): void {
	if (turnsOn === true && !passkeysAccepted(bucket)) {
		throw new AdminError(
			409,
			"Turn on passkeys on the project's Sign-in tab first.",
			{ code: 'passkeys_not_accepted', field: 'requirePasskey' }
		);
	}
}

export async function requirePasskeyPreview(
	bucket: UserBucket,
	client: { clientId: string; requirePasskey: boolean } | undefined,
	turnsOn: boolean | undefined
): Promise<RequirePasskeyPreview | null> {
	if (turnsOn !== true || client?.requirePasskey === true) return null;
	const counts = await signInCounts(bucket);
	const { rpId } = relyingPartyOf(bucket);
	const holding = await getPasskeyStore().holdingIn(bucket._id, rpId, {
		full: true
	});
	const withoutPasskey = Math.max(0, counts.total - holding.length);
	const providerOnly = bucket.passwordLogin
		? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
		: counts.total;
	const holders = client ? await holdersOf(client.clientId, bucket._id) : 0;

	const consequences = [
		withoutPasskey === 0
			? 'Everyone in this project has a confirmed passkey.'
			: `${people(withoutPasskey, 'has', 'have')} no confirmed passkey. They will be asked to create one, or to confirm the one they made, before they can open this application.`,
		...(providerOnly > 0
			? [
					`${people(providerOnly, 'can', 'can')} sign in only through a provider and cannot create a passkey here. They will be turned away.`
				]
			: []),
		...(holders > 0
			? [
					`${people(holders, 'holds', 'hold')} a sign-in to this application now. Whoever did not sign in with a passkey will be asked to sign in again when the application next renews its tokens.`
				]
			: []),
		'The application receives the error unmet_authentication_requirements for each person turned away; make sure it shows a helpful page.'
	];
	return {
		consequences,
		expect: { withoutPasskey, providerOnly, holders },
		changes: ['requirePasskeyOn']
	};
}
