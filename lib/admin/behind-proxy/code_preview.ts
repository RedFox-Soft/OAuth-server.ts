import { getPasskeyStore, getUserStore } from '../../adapters/index.js';
import {
	MAX_END_USER_PAGE,
	type BehindProxyRule,
	type User,
	type UserBucket
} from '../../adapters/types.js';
import { baseWho, gatherConditions } from '../../behind_proxy/decide.js';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { selfServiceState } from '../../totp/self_service.js';
import { signInCounts } from '../buckets/sign_in_preview.js';

/*
 * What asking for a code from an authenticator app, or for a passkey, on a path behind the proxy would do, counted
 * before it is done (specs/128 research R8, specs/143). The protocol is the application setting's
 * (lib/admin/clients/require_code_preview.ts): the first save answers 409 with these, and the change is applied only
 * when repeated with `confirm` and the same counts as `expect`, so the console and an agent consent the same way and
 * to the numbers they were shown.
 *
 * The people counted are those who may reach a path that newly asks for a code or passkey: everyone in the project for
 * a project rule, the members of the named groups for a groups rule. The path's other conditions are not applied, so
 * the numbers are an upper bound and the words say so. Only turning it on or raising two-step to passkey is previewed;
 * keeping, lowering or removing it is not a tightening.
 */

export type BehindProxySignInChange = 'codeConditionOn' | 'passkeyConditionOn';

export interface CodeConditionPreview {
	consequences: string[];
	expect: {
		withoutAuthenticator?: number;
		withoutPasskey?: number;
		providerOnly: number;
	};
	changes: BehindProxySignInChange[];
	paths: string[];
}

/*
 * A fresh condition with a code, or a network facts part whose matching addresses are asked for a sign-in with one
 * (specs/129 FR-022): either way some people reaching the path are asked for a code they may not have.
 */
function asksForCode(rules: readonly BehindProxyRule[], path: string): boolean {
	return gatherConditions(rules, path).some(
		({ condition }) =>
			(condition.kind === 'fresh' && condition.withCode === true) ||
			(condition.kind === 'network' &&
				condition.facts?.outcome.kind === 'sign_in_again' &&
				condition.facts.outcome.withCode === true)
	);
}

/* A fresh condition or network-facts step-up asking for a passkey (specs/143). */
export function asksForPasskey(
	rules: readonly BehindProxyRule[],
	path: string
): boolean {
	return gatherConditions(rules, path).some(
		({ condition }) =>
			(condition.kind === 'fresh' && condition.withPasskey === true) ||
			(condition.kind === 'network' &&
				condition.facts?.outcome.kind === 'sign_in_again' &&
				condition.facts.outcome.withPasskey === true)
	);
}

/* The paths a rule set newly asks a passkey on, compared rule by rule with the one it replaces (specs/143). */
export function pathsNewlyAskingForPasskey(
	before: readonly BehindProxyRule[],
	after: readonly BehindProxyRule[]
): string[] {
	return after
		.filter((rule) => {
			const who = baseWho(rule.who);
			if (who.kind !== 'groups' && who.kind !== 'project') return false;
			return (
				asksForPasskey(after, rule.path) && !asksForPasskey(before, rule.path)
			);
		})
		.map((rule) => rule.path);
}

/* The paths a rule set newly asks a code on (and not a passkey), compared rule by rule with the one it replaces. */
export function pathsNewlyAskingForCode(
	before: readonly BehindProxyRule[],
	after: readonly BehindProxyRule[]
): string[] {
	return after
		.filter((rule) => {
			const who = baseWho(rule.who);
			if (who.kind !== 'groups' && who.kind !== 'project') return false;
			/* Lowering passkey -> code is a loosening, not a tightening; raising -> passkey is previewed as passkey. */
			if (asksForPasskey(before, rule.path) || asksForPasskey(after, rule.path))
				return false;
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
export async function groupMembers(
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
	const passkeyPaths = pathsNewlyAskingForPasskey(before, after);
	const codePaths = pathsNewlyAskingForCode(before, after);
	if (passkeyPaths.length === 0 && codePaths.length === 0) return null;

	const paths = [...new Set([...passkeyPaths, ...codePaths])];
	const passwords = bucket.passwordLogin;
	const changes: BehindProxySignInChange[] = [];
	const consequences: string[] = [];
	const expect: CodeConditionPreview['expect'] = { providerOnly: 0 };

	/* Provider-only people across the union of all newly tightened paths. */
	const allAudiences = after
		.filter((rule) => paths.includes(rule.path))
		.map((rule) => baseWho(rule.who));
	let sharedCounts: Awaited<ReturnType<typeof signInCounts>> | undefined;
	const projectCounts = async () =>
		(sharedCounts ??= await signInCounts(bucket));

	if (allAudiences.some((who) => who.kind === 'project')) {
		const counts = await projectCounts();
		expect.providerOnly = passwords
			? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
			: counts.total;
	} else {
		const groupIds = new Set(
			allAudiences.flatMap((who) => (who.kind === 'groups' ? who.groupIds : []))
		);
		const members = [
			...(await groupMembers(bucket._id, groupIds, false)).values()
		];
		expect.providerOnly = passwords
			? members.filter((user) => user.passwordSet === false).length
			: members.length;
	}

	if (passkeyPaths.length > 0) {
		changes.push('passkeyConditionOn');
		const audiences = after
			.filter((rule) => passkeyPaths.includes(rule.path))
			.map((rule) => baseWho(rule.who));
		const holding = await getPasskeyStore().holdingIn(
			bucket._id,
			rpIdFor(bucket),
			{ full: true }
		);
		let withoutPasskey: number;
		if (audiences.some((who) => who.kind === 'project')) {
			const counts = await projectCounts();
			withoutPasskey = Math.max(0, counts.total - holding.length);
		} else {
			const groupIds = new Set(
				audiences.flatMap((who) => (who.kind === 'groups' ? who.groupIds : []))
			);
			const members = [
				...(await groupMembers(bucket._id, groupIds, false)).values()
			];
			const holdingIds = new Set(holding.map((holder) => holder.accountId));
			withoutPasskey = members.filter(
				(user) => !holdingIds.has(user._id)
			).length;
		}
		expect.withoutPasskey = withoutPasskey;
		const where = passkeyPaths.join(', ');
		consequences.push(
			withoutPasskey === 0
				? `Everyone who may open ${where} has a confirmed passkey.`
				: `${people(withoutPasskey, 'who may open it has', 'who may open it have')} no confirmed passkey yet. People who sign in with a password can create one on the refusal page; people who sign in only through a provider will be turned away.`
		);
	}

	if (codePaths.length > 0) {
		changes.push('codeConditionOn');
		const audiences = after
			.filter((rule) => codePaths.includes(rule.path))
			.map((rule) => baseWho(rule.who));
		let withoutAuthenticator: number;
		if (audiences.some((who) => who.kind === 'project')) {
			const counts = await projectCounts();
			withoutAuthenticator = passwords
				? counts.passwordWithoutAuthenticator
				: 0;
		} else {
			const groupIds = new Set(
				audiences.flatMap((who) => (who.kind === 'groups' ? who.groupIds : []))
			);
			const members = [
				...(await groupMembers(bucket._id, groupIds, passwords)).values()
			];
			const withPassword = members.filter((user) => user.passwordSet !== false);
			withoutAuthenticator = passwords ? withPassword.length : 0;
		}
		expect.withoutAuthenticator = withoutAuthenticator;
		const selfService = (await selfServiceState(bucket)) === 'on';
		const where = codePaths.join(', ');
		consequences.push(
			withoutAuthenticator === 0
				? `Everyone who may open ${where} with a password has an authenticator app.`
				: selfService
					? `${people(withoutAuthenticator, 'who may open it with a password has', 'who may open it with a password have')} no authenticator app. They will be asked to set one up first.`
					: `${people(withoutAuthenticator, 'who may open it with a password has', 'who may open it with a password have')} no authenticator app, and this project does not let people set one up themselves. They will be turned away.`
		);
	}

	if (expect.providerOnly > 0) {
		consequences.push(
			`${people(expect.providerOnly, 'who may open it can', 'who may open it can')} sign in only through a provider. They will be turned away.`
		);
	}
	consequences.push(
		passkeyPaths.length > 0 && codePaths.length === 0
			? 'People who hold a sign-in to the app without a passkey now are asked to sign in again, with a passkey, the next time they open these paths.'
			: 'People who hold a sign-in to the app now are asked to sign in again the next time they open these paths.'
	);

	return {
		consequences,
		expect,
		changes,
		paths
	};
}
