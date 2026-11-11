import { getUserStore } from '../../adapters/index.js';
import {
	MAX_END_USER_PAGE,
	type BehindProxyRule,
	type User,
	type UserBucket
} from '../../adapters/types.js';
import { baseWho, gatherConditions } from '../../behind_proxy/decide.js';
import { selfServiceState } from '../../totp/self_service.js';
import { signInCounts } from '../buckets/sign_in_preview.js';

/*
 * What asking for a code from an authenticator app on a path behind the proxy would do, counted before it is done
 * (specs/128 research R8). The protocol is the application setting's (lib/admin/clients/require_code_preview.ts): the
 * first save answers 409 with these, and the change is applied only when repeated with `confirm` and the same counts
 * as `expect`, so the console and an agent consent the same way and to the numbers they were shown.
 *
 * The people counted are those who may reach a path that newly asks for a code: everyone in the project for a project
 * rule, the members of the named groups for a groups rule. The path's other conditions are not applied, so the numbers
 * are an upper bound and the words say so. Only turning it on is previewed; keeping or removing it is not a tightening.
 */

export interface CodeConditionPreview {
	consequences: string[];
	expect: { withoutAuthenticator: number; providerOnly: number };
	changes: ['codeConditionOn'];
	paths: string[];
}

function asksForCode(rules: readonly BehindProxyRule[], path: string): boolean {
	return gatherConditions(rules, path).some(
		({ condition }) => condition.kind === 'fresh' && condition.withCode === true
	);
}

/* The paths a rule set newly asks a code on, compared rule by rule with the one it replaces. */
export function pathsNewlyAskingForCode(
	before: readonly BehindProxyRule[],
	after: readonly BehindProxyRule[]
): string[] {
	return after
		.filter((rule) => {
			const who = baseWho(rule.who);
			if (who.kind !== 'groups' && who.kind !== 'project') return false;
			return asksForCode(after, rule.path) && !asksForCode(before, rule.path);
		})
		.map((rule) => rule.path);
}

/* "Up to 1 person who … has", "Up to 2 people who … have": the verb follows the count; always a sentence start. */
function people(n: number, one: string, many: string): string {
	return n === 1
		? `Up to 1 person ${one}`
		: `Up to ${String(n)} people ${many}`;
}

/*
 * Members of the groups, each person once, read through the people list's own filters: those without an authenticator,
 * or everyone when password sign-in is off and nobody could give a code.
 */
async function groupMembers(
	bucketId: string,
	groupIds: Iterable<string>,
	withoutAuthenticatorOnly: boolean
): Promise<Map<string, User>> {
	const found = new Map<string, User>();
	const store = getUserStore(bucketId);
	for (const memberOf of groupIds) {
		for (let startIndex = 1; ; startIndex += MAX_END_USER_PAGE) {
			const page = await store.query(
				withoutAuthenticatorOnly
					? { memberOf, totpEnrolled: false }
					: { memberOf },
				{ startIndex, count: MAX_END_USER_PAGE }
			);
			for (const user of page.users) found.set(user._id, user);
			if (startIndex + MAX_END_USER_PAGE > page.totalResults) break;
		}
	}
	return found;
}

export async function codeConditionPreview(
	bucket: UserBucket,
	before: readonly BehindProxyRule[],
	after: readonly BehindProxyRule[]
): Promise<CodeConditionPreview | null> {
	const paths = pathsNewlyAskingForCode(before, after);
	if (paths.length === 0) return null;
	const audiences = after
		.filter((rule) => paths.includes(rule.path))
		.map((rule) => baseWho(rule.who));
	const passwords = bucket.passwordLogin;

	let withoutAuthenticator: number;
	let providerOnly: number;
	if (audiences.some((who) => who.kind === 'project')) {
		const counts = await signInCounts(bucket);
		withoutAuthenticator = passwords ? counts.passwordWithoutAuthenticator : 0;
		providerOnly = passwords
			? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
			: counts.total;
	} else {
		const groupIds = new Set(
			audiences.flatMap((who) => (who.kind === 'groups' ? who.groupIds : []))
		);
		const members = [
			...(await groupMembers(bucket._id, groupIds, passwords)).values()
		];
		const withPassword = members.filter((user) => user.passwordSet !== false);
		withoutAuthenticator = passwords ? withPassword.length : 0;
		providerOnly = passwords
			? members.length - withPassword.length
			: members.length;
	}
	const selfService = (await selfServiceState(bucket)) === 'on';
	const where = paths.join(', ');

	const consequences = [
		withoutAuthenticator === 0
			? `Everyone who may open ${where} with a password has an authenticator app.`
			: selfService
				? `${people(withoutAuthenticator, 'who may open it with a password has', 'who may open it with a password have')} no authenticator app. They will be asked to set one up first.`
				: `${people(withoutAuthenticator, 'who may open it with a password has', 'who may open it with a password have')} no authenticator app, and this project does not let people set one up themselves. They will be turned away.`,
		...(providerOnly > 0
			? [
					`${people(providerOnly, 'who may open it can', 'who may open it can')} sign in only through a provider. They will be turned away.`
				]
			: []),
		'People who hold a sign-in to the app now are asked to sign in again, with a code, the next time they open these paths.'
	];
	return {
		consequences,
		expect: { withoutAuthenticator, providerOnly },
		changes: ['codeConditionOn'],
		paths
	};
}
