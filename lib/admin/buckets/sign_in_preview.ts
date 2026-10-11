import { getProjectStore, getUserStore } from '../../adapters/index.js';
import type { EndUserTally, UserBucket } from '../../adapters/types.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
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
	'passwordsOff' | 'verificationOn' | 'authenticatorOn' | 'signUpOpen';

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
}

export interface SignInCounts extends EndUserTally {
	/* Present on the default bucket only: the projects whose sign-in lands there. */
	projects?: number;
}

/*
 * The bucket's tally against its enabled providers, and on the default bucket the projects signing in at
 * it. One function for the summary and the preview, so the numbers an operator reads on the tab are the
 * numbers the confirmation must repeat.
 */
export async function signInCounts(
	bucket: Pick<UserBucket, '_id' | 'federation'>
): Promise<SignInCounts> {
	const [tally, projects] = await Promise.all([
		getUserStore(bucket._id).tally({
			enabledProviderIds: bucket.federation
				.filter((provider) => provider.enabled)
				.map((provider) => provider.id)
		}),
		bucket._id === DEFAULT_BUCKET_ID ? projectsAtTheDefault() : undefined
	]);
	return projects === undefined ? tally : { ...tally, projects };
}

/*
 * A project with no bucket of its own signs in at the default one (`resolveBucketForRequest`), so it is
 * reached by a change there as surely as one that names it.
 */
async function projectsAtTheDefault(): Promise<number> {
	return (await getProjectStore().list()).filter(
		(project) => !project.bucketId || project.bucketId === DEFAULT_BUCKET_ID
	).length;
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
	if (changes.length === 0) return null;

	const counts = await signInCounts(bucket);
	const people = consoleBucket ? 'administrator' : 'user';
	const consequences: string[] = [];
	const expect: Record<string, number> = {};

	for (const change of changes) {
		switch (change) {
			case 'passwordsOff': {
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
			case 'signUpOpen':
				consequences.push(
					consoleBucket
						? 'Anyone who can reach the sign-in page can create an administrator account.'
						: 'Anyone who can reach the sign-in page can create an account.'
				);
				break;
		}
	}

	if (counts.projects !== undefined) {
		expect.projects = counts.projects;
		consequences.push(
			`This changes sign-in for ${plural(counts.projects, 'project')}.`
		);
	}
	return { consequences, expect, changes };
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
