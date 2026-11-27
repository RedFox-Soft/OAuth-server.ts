import {
	adapter,
	getBehindProxyAppStore,
	getPasskeyStore,
	getProtectedResourceStore,
	getUserStore
} from '../../adapters/index.js';
import type {
	EndUserTally,
	PasswordGuessingSetting,
	UserBucket
} from '../../adapters/types.js';
import { countsFor } from '../../attacker_list/counters.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { otherWayIn, usersOf } from '../../passkeys/ways_in.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../consts.js';
import {
	loadReachabilityState,
	reachableThroughProvider
} from '../federation/reachability.js';

/*
 * What a sign-in change would do to the people of a bucket, counted before it is made (specs/083).
 *
 * The bucket PATCH answers this as a 409 for every change that tightens who can get in, and applies it only
 * when it is repeated with `confirm` and the same counts as `expect` — the address change's protocol
 * (routes.ts, `bucket.address.change`), so an agent and the console consent the same way, and to the
 * numbers they were shown rather than to whatever the bucket holds by the time they answer.
 *
 * Loosening is never previewed: turning a requirement off, closing sign-up, renaming. Neither is opening
 * sign-up on an ordinary bucket, which is what a bucket is for; on the two served at the root it is
 * previewed because anyone who reaches this server's own sign-in page could then make an account — on the
 * console's, an administrator account.
 */

export type SignInChange =
	| 'passwordsOff'
	| 'verificationOn'
	| 'authenticatorOn'
	| 'signUpOpen'
	| 'guessingRefuseOn'
	| 'passkeysOff'
	| 'passkeyAppsOff'
	| 'passkeyApisOff'
	| 'passkeyPathsOff'
	| 'consolePasskeyOn';

export interface SignInPreview {
	consequences: string[];
	expect: Record<string, number>;
	changes: SignInChange[];
}

interface SignInPatch {
	passwordLogin?: boolean;
	registrationOpen?: boolean;
	emailVerificationRequired?: boolean;
	totpRequired?: boolean;
	passwordGuessing?: Pick<PasswordGuessingSetting, 'mode'>;
	passkeyLogin?: boolean;
	passkeyRecovery?: boolean;
	consolePasskeyRequired?: boolean;
}

export interface SignInCounts extends EndUserTally {
	/* Present on the default bucket only: the applications whose sign-in lands there. */
	applications?: number;
}

/*
 * The bucket's tally against its enabled providers, and on the default bucket the applications signing in
 * at it. One function for the summary and the preview, so the numbers an operator reads on the tab are the
 * numbers the confirmation must repeat.
 */
export async function signInCounts(
	bucket: Pick<UserBucket, '_id' | 'federation'>
): Promise<SignInCounts> {
	const [tally, applications] = await Promise.all([
		getUserStore(bucket._id).tally({
			enabledProviderIds: bucket.federation
				.filter((provider) => provider.enabled)
				.map((provider) => provider.id)
		}),
		bucket._id === DEFAULT_BUCKET_ID ? applicationsAtTheDefault() : undefined
	]);
	return applications === undefined ? tally : { ...tally, applications };
}

/* Every application of the Default bucket is reached by a change there. */
async function applicationsAtTheDefault(): Promise<number> {
	return (await adapter('Client').findByIndexed('bucketId', DEFAULT_BUCKET_ID))
		.length;
}

function plural(n: number, one: string, many = `${one}s`): string {
	return `${n} ${n === 1 ? one : many}`;
}

/* `null` when nothing in `patch` tightens sign-in; otherwise each consequence, its count and its kind. */
export async function signInPreview(
	bucket: UserBucket,
	patch: SignInPatch
): Promise<SignInPreview | null> {
	const turnsOn = (field: keyof SignInPatch) =>
		patch[field] === true && !bucket[field];
	const passwordsOff = patch.passwordLogin === false && bucket.passwordLogin;
	const passwordsAfter = patch.passwordLogin ?? bucket.passwordLogin;
	const consoleBucket = bucket._id === ADMIN_BUCKET_ID;
	const atTheRoot = consoleBucket || bucket._id === DEFAULT_BUCKET_ID;

	const changes: SignInChange[] = [];
	if (passwordsOff) changes.push('passwordsOff');
	if (turnsOn('emailVerificationRequired')) changes.push('verificationOn');
	/* Inert while passwords are off — it governs the password door only — so nobody is asked anything. */
	if (turnsOn('totpRequired') && passwordsAfter)
		changes.push('authenticatorOn');
	if (turnsOn('registrationOpen') && atTheRoot) changes.push('signUpOpen');
	/*
	 * Refusing sign-ins from listed addresses (specs/125): shared addresses are on shared lists, so the numbers of the
	 * last 7 days — how many came from listed addresses and how many of those had the right password — are what the
	 * administrator consents to.
	 */
	if (
		patch.passwordGuessing?.mode === 'refuse' &&
		(bucket.passwordGuessing?.mode ?? 'count') !== 'refuse'
	) {
		changes.push('guessingRefuseOn');
	}
	/*
	 * Turning passkeys off (specs/139 research R21) deletes none, but refuses them all: only a tightening when someone
	 * holds a passkey and no other way in, which is counted below, so an ordinary turn-off applies at once.
	 */
	const passkeyOnly =
		patch.passkeyLogin === false && bucket.passkeyLogin === true
			? await passkeyOnlyPeople(bucket, passwordsAfter)
			: 0;
	if (passkeyOnly > 0) changes.push('passkeysOff');
	/* An application, API, or proxy path that requires a passkey (specs/142, 143) then refuses everyone; named, since each needs a decision. */
	const turningPasskeysOff =
		patch.passkeyLogin === false && bucket.passkeyLogin === true;
	const [requiringPasskey, requiringPasskeyApis, requiringPasskeyPaths] =
		turningPasskeysOff
			? await Promise.all([
					appsRequiringPasskey(bucket._id),
					apisRequiringPasskey(bucket._id),
					pathsRequiringPasskey(bucket._id)
				])
			: [[], [], []];
	if (requiringPasskey.length > 0) changes.push('passkeyAppsOff');
	if (requiringPasskeyApis.length > 0) changes.push('passkeyApisOff');
	if (requiringPasskeyPaths.length > 0) changes.push('passkeyPathsOff');
	if (
		consoleBucket &&
		patch.consolePasskeyRequired === true &&
		bucket.consolePasskeyRequired !== true
	) {
		changes.push('consolePasskeyOn');
	}
	if (changes.length === 0) return null;

	const counts = await signInCounts(bucket);
	const people = consoleBucket ? 'administrator' : 'user';
	const consequences: string[] = [];
	const expect: Record<string, number> = {};

	for (const change of changes) {
		switch (change) {
			case 'passwordsOff': {
				const passkeysAfter =
					patch.passkeyLogin ?? bucket.passkeyLogin === true;
				const recoveryAfter =
					patch.passkeyRecovery ?? bucket.passkeyRecovery === true;
				if (passkeysAfter) {
					const holders = new Set(
						(
							await getPasskeyStore().holdingIn(bucket._id, rpIdFor(bucket))
						).map((holder) => holder.accountId)
					);
					const accounts = (await getUserStore(bucket._id).list()).filter(
						(user) => canSignIn(user)
					);
					const providers = consoleBucket
						? (await loadReachabilityState()).providers
						: bucket.federation;
					const without = accounts.filter(
						(user) =>
							!holders.has(user._id) &&
							!reachableThroughProvider(user, providers)
					);
					expect.withoutWayIn = without.length;
					const shown = consoleBucket ? without : without.slice(0, 20);
					const more = without.length - shown.length;
					const names =
						shown.length > 0
							? `: ${shown.map((user) => user.email).join(', ')}${more > 0 ? `, and ${String(more)} more` : ''}.`
							: '.';
					const noun = consoleBucket ? 'administrator' : 'user';
					consequences.push(
						`${without.length} of ${plural(accounts.length, noun)} ${without.length === 1 ? 'has' : 'have'} neither a working passkey nor a linked identity provider and will not be able to sign in${names}`
					);
					if (!consoleBucket && !recoveryAfter) {
						consequences.push(
							'Self-service passkey recovery is off: anyone who loses their passkeys will need an administrator to send them a setup link.'
						);
					}
					break;
				}
				if (consoleBucket) {
					/*
					 * Named, not only counted: these are colleagues, few, and the person turning passwords off has
					 * to tell each of them. Read as the sign-in readiness reads it, so an address outside a
					 * provider's admitted domains counts as unlinked there too.
					 */
					const state = await loadReachabilityState();
					const accounts = (await getUserStore(ADMIN_BUCKET_ID).list()).filter(
						(user) => canSignIn(user)
					);
					const unlinked = accounts.filter(
						(user) => !reachableThroughProvider(user, state.providers)
					);
					expect.withoutEnabledLink = unlinked.length;
					consequences.push(
						`${unlinked.length} of ${plural(accounts.length, 'administrator')} ${unlinked.length === 1 ? 'has' : 'have'} no linked account at an enabled identity provider and could no longer sign in` +
							(unlinked.length > 0
								? `: ${unlinked.map((user) => user.email).join(', ')}.`
								: '.')
					);
				} else {
					expect.withoutEnabledLink = counts.withoutEnabledLink;
					consequences.push(
						`${counts.withoutEnabledLink} of ${plural(counts.total, 'user')} ${counts.withoutEnabledLink === 1 ? 'has' : 'have'} no account at an enabled identity provider and could no longer sign in.`
					);
				}
				break;
			}
			case 'verificationOn':
				expect.unverified = counts.unverified;
				consequences.push(
					`${plural(counts.unverified, people)} ${counts.unverified === 1 ? "hasn't" : "haven't"} verified their address; each is sent a message at their next sign-in and cannot continue until they follow it.`
				);
				break;
			case 'authenticatorOn':
				expect.passwordWithoutAuthenticator =
					counts.passwordWithoutAuthenticator;
				consequences.push(
					`${plural(counts.passwordWithoutAuthenticator, `password ${people}`)} ${counts.passwordWithoutAuthenticator === 1 ? 'has' : 'have'} no authenticator yet; they set one up at their next sign-in.`
				);
				break;
			case 'guessingRefuseOn': {
				const listed = await countsFor(bucket._id);
				expect.listedAttempts = listed.listedAttempts;
				expect.listedRightPassword = listed.listedRightPassword;
				consequences.push(
					`In the last 7 days ${plural(listed.listedAttempts, 'password sign-in')} came from addresses on FoxTrust's list, ${String(listed.listedRightPassword)} of them with the right password; from now on such an address is refused once it has failed 3 passwords here within an hour, or at once when FoxTrust corroborates it.`
				);
				break;
			}
			case 'passkeysOff':
				expect.passkeyOnly = passkeyOnly;
				consequences.push(
					`${plural(passkeyOnly, consoleBucket ? 'administrator' : 'person', consoleBucket ? 'administrators' : 'people')} can only sign in with a passkey; they will not be able to sign in.`
				);
				break;
			case 'consolePasskeyOn': {
				const accounts = (await getUserStore(ADMIN_BUCKET_ID).list()).filter(
					(user) => canSignIn(user)
				);
				const holders = new Set(
					(
						await getPasskeyStore().holdingIn(ADMIN_BUCKET_ID, rpIdFor(bucket))
					).map((holder) => holder.accountId)
				);
				const without = accounts.filter((user) => !holders.has(user._id));
				expect.withoutPasskey = without.length;
				consequences.push(
					`${without.length} of ${plural(accounts.length, 'administrator')} ${without.length === 1 ? 'has' : 'have'} no passkey and won't be able to sign in to the console or connect an agent` +
						(without.length > 0
							? `: ${without.map((user) => user.email).join(', ')}.`
							: '.')
				);
				break;
			}
			case 'passkeyAppsOff':
				expect.appsRequiringPasskey = requiringPasskey.length;
				consequences.push(
					`${plural(requiringPasskey.length, 'application')} ${requiringPasskey.length === 1 ? 'requires' : 'require'} a passkey: ${requiringPasskey.join(', ')}. Nobody will be able to open ${requiringPasskey.length === 1 ? 'it' : 'them'} until passkeys are back on, or the requirement is removed.`
				);
				break;
			case 'passkeyApisOff':
				expect.apisRequiringPasskey = requiringPasskeyApis.length;
				consequences.push(
					`${plural(requiringPasskeyApis.length, 'API')} ${requiringPasskeyApis.length === 1 ? 'requires' : 'require'} a passkey: ${requiringPasskeyApis.join(', ')}. Nobody will be able to use ${requiringPasskeyApis.length === 1 ? 'it' : 'them'} until passkeys are back on, or the requirement is removed.`
				);
				break;
			case 'passkeyPathsOff':
				expect.pathsRequiringPasskey = requiringPasskeyPaths.length;
				consequences.push(
					`${plural(requiringPasskeyPaths.length, 'proxy path')} ${requiringPasskeyPaths.length === 1 ? 'requires' : 'require'} a passkey: ${requiringPasskeyPaths.join(', ')}. Nobody will be able to open ${requiringPasskeyPaths.length === 1 ? 'it' : 'them'} until passkeys are back on, or the requirement is removed.`
				);
				break;
			case 'signUpOpen':
				consequences.push(
					consoleBucket
						? 'Anyone who can reach the sign-in page can create an administrator account.'
						: 'Anyone who can reach the sign-in page can create an account.'
				);
				break;
		}
	}

	if (counts.applications !== undefined) {
		expect.applications = counts.applications;
		consequences.push(
			`This changes sign-in for ${plural(counts.applications, 'application')}.`
		);
	}
	return { consequences, expect, changes };
}

/*
 * The applications of the bucket that require a passkey (specs/142), by the name they are shown under: a change that
 * stops the project's passkeys working leaves each refusing everyone.
 */
export async function appsRequiringPasskey(
	bucketId: string
): Promise<string[]> {
	const clients = await adapter('Client').findByIndexed('bucketId', bucketId);
	return clients
		.filter((client) => client['signIn.requirePasskey'] === true)
		.map((client) =>
			typeof client.client_name === 'string' && client.client_name
				? client.client_name
				: String(client.client_id ?? client.clientId)
		);
}

/* The declared APIs of the bucket that require a passkey (specs/143), by name. */
export async function apisRequiringPasskey(
	bucketId: string
): Promise<string[]> {
	const resources = await getProtectedResourceStore().listByBucket(bucketId);
	return resources
		.filter((resource) => resource.requirePasskey === true)
		.map((resource) => resource.name || resource.identifier);
}

/* The behind-proxy app paths of the bucket that ask for a passkey (specs/143), as `<host> <path>`. */
export async function pathsRequiringPasskey(
	bucketId: string
): Promise<string[]> {
	const apps = await getBehindProxyAppStore().listByBucket(bucketId);
	const found: string[] = [];
	for (const app of apps) {
		const host = new URL(app.address).host;
		for (const rule of app.rules) {
			if (rule.who.kind !== 'conditional') continue;
			const asks = rule.who.conditions.some(
				(condition) =>
					(condition.kind === 'fresh' && condition.withPasskey === true) ||
					(condition.kind === 'network' &&
						condition.facts?.outcome.kind === 'sign_in_again' &&
						condition.facts.outcome.withPasskey === true)
			);
			if (asks) found.push(`${host} ${rule.path}`);
		}
	}
	return found;
}

/*
 * The people of the bucket who hold a passkey that signs in here and would have no other way in, with passwords as the
 * change leaves them (lib/passkeys/ways_in.ts). Only passkeys of the current site and not refused as copied count:
 * someone holding nothing else was locked out already (specs/140 research R6).
 */
async function passkeyOnlyPeople(
	bucket: UserBucket,
	passwordsAfter: boolean
): Promise<number> {
	const holders = await getPasskeyStore().holdingIn(
		bucket._id,
		rpIdFor(bucket)
	);
	const people = await usersOf(
		bucket._id,
		holders.map((holder) => holder.accountId)
	);
	return people.filter(
		(user) => !otherWayIn(bucket, user, { passwordsOpen: passwordsAfter })
	).length;
}

/* The confirmation is of the counts previewed: every one of them, as fresh, and nothing else compared. */
export function sameExpect(
	given: Readonly<Record<string, number | undefined>> | undefined,
	fresh: Readonly<Record<string, number>>
): boolean {
	return (
		given !== undefined &&
		Object.entries(fresh).every(([key, count]) => given[key] === count)
	);
}
