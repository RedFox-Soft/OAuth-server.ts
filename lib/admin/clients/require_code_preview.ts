import { adapter } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { Grant } from '../../models/grant.js';
import { selfServiceState } from '../../totp/self_service.js';
import { signInCounts } from '../buckets/sign_in_preview.js';

/*
 * What making an application require a code from an authenticator app would do, counted before it is done (specs/127
 * research R8). The project PATCH's protocol (sign_in_preview.ts): the first call answers 409 with these, and the change
 * is applied only when it is repeated with `confirm` and the same counts as `expect`, so an agent and the console consent
 * the same way and to the numbers they were shown.
 *
 * Sign-ins are not recorded per application (lib/activity), so "who used it lately" cannot be counted. What can: the
 * project's people the requirement turns away or sends to set one up — any of them may open the app — and the people
 * who hold a sign-in to it now, whose renewals stop working.
 *
 * Only turning it on is previewed. Turning it off, or leaving it, is not a tightening.
 */

export interface RequireCodePreview {
	consequences: string[];
	expect: {
		withoutAuthenticator: number;
		providerOnly: number;
		holders: number;
	};
	changes: ['requireCodeOn'];
}

/* "1 person who signs in … has", "2 people who sign in … have": the verb follows the count. */
function people(n: number, one: string, many: string): string {
	return n === 1 ? `1 person ${one}` : `${n} people ${many}`;
}

/* Distinct people with a live sign-in to the application in this project. */
async function holdersOf(clientId: string, bucketId: string): Promise<number> {
	const stored = await adapter('Grant').findByOwner('clientId', clientId);
	const grants = await Promise.all(
		stored.map((record) => Grant.fromStored(record))
	);
	return new Set(
		grants
			.filter(
				(grant): grant is Grant =>
					grant !== undefined &&
					!grant.isExpired &&
					(grant.payload.bucketId === undefined ||
						grant.payload.bucketId === bucketId)
			)
			.map((grant) => grant.payload.accountId)
	).size;
}

export async function requireCodePreview(
	bucket: UserBucket,
	client: { clientId: string; requireCode: boolean } | undefined,
	turnsOn: boolean | undefined
): Promise<RequireCodePreview | null> {
	if (turnsOn !== true || client?.requireCode === true) return null;
	const counts = await signInCounts(bucket);
	const passwords = bucket.passwordLogin;
	const withoutAuthenticator = passwords
		? counts.passwordWithoutAuthenticator
		: 0;
	const providerOnly = passwords
		? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
		: counts.total;
	const holders = client ? await holdersOf(client.clientId, bucket._id) : 0;
	const selfService = (await selfServiceState(bucket)) === 'on';

	const consequences = [
		withoutAuthenticator === 0
			? 'Everyone who signs in with a password here has an authenticator app.'
			: selfService
				? `${people(withoutAuthenticator, 'who signs in with a password has', 'who sign in with a password have')} no authenticator app. They will be asked to set one up first.`
				: `${people(withoutAuthenticator, 'who signs in with a password has', 'who sign in with a password have')} no authenticator app, and this project does not let people set one up themselves. They will be turned away.`,
		...(providerOnly > 0
			? [
					`${people(providerOnly, 'can', 'can')} sign in only through a provider. They will be turned away.`
				]
			: []),
		...(holders > 0
			? [
					`${people(holders, 'holds', 'hold')} a sign-in to this application now. Whoever signed in without a code will be asked to sign in again when the application next renews its tokens.`
				]
			: []),
		'The application receives the error unmet_authentication_requirements for each person turned away; make sure it shows a helpful page.'
	];
	return {
		consequences,
		expect: { withoutAuthenticator, providerOnly, holders },
		changes: ['requireCodeOn']
	};
}
