import { adapter, getPasskeyStore } from '../../adapters/index.js';
import type { ProtectedResource, UserBucket } from '../../adapters/types.js';
import { Grant } from '../../models/grant.js';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { selfServiceState } from '../../totp/self_service.js';
import { groupMembers } from '../behind-proxy/code_preview.js';
import { signInCounts } from '../buckets/sign_in_preview.js';

/*
 * What making an API require a code from an authenticator app, a passkey, or a sign-in every so often, would do,
 * counted before it is done (specs/130 research R9, specs/143 R7). The protocol is the application setting's
 * (lib/admin/clients/require_code_preview.ts): the first save answers 409 with these, and the change applies only when
 * repeated with `confirm` and the same counts as `expect`, so the console and an agent consent the same way and to the
 * numbers they were shown.
 *
 * Usage is not recorded per API, so "who used it lately" cannot be counted. What can: the people the API can reach
 * (the project, or the members of its group condition) who have no authenticator app or no confirmed passkey, or who
 * sign in only through a provider, as an upper bound; the people holding a live sign-in that includes this API through
 * the project's own applications; and, by name, the applications that act for no one or sign in by assertion, which
 * never meet it.
 *
 * Only a tightening is previewed: turning two-step or passkey on, raising two-step to a passkey, or setting or
 * shortening the interval. Lowering from a passkey to two-step or off applies without a preview.
 */

export type ApiSignInChange =
	'apiRequireCodeOn' | 'apiRequirePasskeyOn' | 'apiSignInEvery';

export interface ApiSignInPreview {
	consequences: string[];
	expect: {
		withoutAuthenticator?: number;
		withoutPasskey?: number;
		providerOnly: number;
		holders: number;
	};
	changes: ApiSignInChange[];
	machineApps: string[];
	assertionApps: string[];
}

export interface RequirementChange {
	requireCode?: boolean;
	requirePasskey?: boolean;
	signInEveryMinutes?: number | null;
}

const ASSERTION_GRANTS = new Set([
	'urn:ietf:params:oauth:grant-type:jwt-bearer'
]);

/* "Up to 1 person who … has", "Up to 2 people who … have": the verb follows the count. */
function people(n: number, one: string, many: string): string {
	return n === 1
		? `Up to 1 person ${one}`
		: `Up to ${String(n)} people ${many}`;
}

function changesOf(
	before: Pick<
		ProtectedResource,
		'requireCode' | 'requirePasskey' | 'signInEveryMinutes'
	>,
	next: RequirementChange
): ApiSignInChange[] {
	const changes: ApiSignInChange[] = [];
	const passkeyOn =
		next.requirePasskey === true && before.requirePasskey !== true;
	if (passkeyOn) {
		changes.push('apiRequirePasskeyOn');
	} else if (
		before.requirePasskey !== true &&
		next.requireCode === true &&
		before.requireCode !== true
	) {
		changes.push('apiRequireCodeOn');
	}
	const minutes = next.signInEveryMinutes;
	if (
		typeof minutes === 'number' &&
		(before.signInEveryMinutes === undefined ||
			minutes < before.signInEveryMinutes)
	) {
		changes.push('apiSignInEvery');
	}
	return changes;
}

/* The groups the API's own condition admits, or undefined when the whole project may call it. */
function audienceGroups(
	api: Pick<ProtectedResource, 'tools'> | undefined
): string[] | undefined {
	const condition = api?.tools?.access?.conditions.find(
		(candidate) => candidate.kind === 'group'
	);
	return condition?.kind === 'group' ? condition.groupIds : undefined;
}

async function audienceCounts(
	bucket: UserBucket,
	groupIds: string[] | undefined
): Promise<{ withoutAuthenticator: number; providerOnly: number }> {
	const passwords = bucket.passwordLogin;
	if (groupIds === undefined) {
		const counts = await signInCounts(bucket);
		return {
			withoutAuthenticator: passwords ? counts.passwordWithoutAuthenticator : 0,
			providerOnly: passwords
				? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
				: counts.total
		};
	}
	const members = [
		...(await groupMembers(bucket._id, groupIds, passwords)).values()
	];
	const withPassword = members.filter((user) => user.passwordSet !== false);
	return {
		withoutAuthenticator: passwords ? withPassword.length : 0,
		providerOnly: passwords
			? members.length - withPassword.length
			: members.length
	};
}

async function audiencePasskeyCounts(
	bucket: UserBucket,
	groupIds: string[] | undefined
): Promise<{ withoutPasskey: number; providerOnly: number }> {
	const passwords = bucket.passwordLogin;
	const holding = await getPasskeyStore().holdingIn(
		bucket._id,
		rpIdFor(bucket),
		{ full: true }
	);
	if (groupIds === undefined) {
		const counts = await signInCounts(bucket);
		return {
			withoutPasskey: Math.max(0, counts.total - holding.length),
			providerOnly: passwords
				? counts.withoutAuthenticator - counts.passwordWithoutAuthenticator
				: counts.total
		};
	}
	const members = [
		...(await groupMembers(bucket._id, groupIds, false)).values()
	];
	const holdingIds = new Set(holding.map((holder) => holder.accountId));
	const withoutPasskey = members.filter(
		(user) => !holdingIds.has(user._id)
	).length;
	const providerOnly = passwords
		? members.filter((user) => user.passwordSet === false).length
		: members.length;
	return { withoutPasskey, providerOnly };
}

/*
 * The project's applications, by name: those that receive tokens for no one, and those that sign in by assertion. A
 * client metadata document has no record, so none of these is ever one.
 */
async function appsNeverMeetingIt(bucketId: string): Promise<{
	machineApps: string[];
	assertionApps: string[];
	clientIds: string[];
}> {
	const stored = (await adapter('Client').findByIndexed(
		'bucketId',
		bucketId
	)) as Record<string, unknown>[];
	const nameOf = (record: Record<string, unknown>) =>
		typeof record.clientName === 'string' && record.clientName !== ''
			? record.clientName
			: String(record.clientId);
	const machineApps: string[] = [];
	const assertionApps: string[] = [];
	for (const record of stored) {
		const grants = Array.isArray(record.grantTypes) ? record.grantTypes : [];
		if (grants.includes('client_credentials')) machineApps.push(nameOf(record));
		if (grants.some((grant) => ASSERTION_GRANTS.has(String(grant)))) {
			assertionApps.push(nameOf(record));
		}
	}
	return {
		machineApps: machineApps.sort(),
		assertionApps: assertionApps.sort(),
		clientIds: stored.map((record) => String(record.clientId))
	};
}

/* Distinct people with a live sign-in that includes the API, through the project's registered applications. */
async function holdersOf(
	identifier: string,
	clientIds: readonly string[],
	bucketId: string
): Promise<number> {
	const holders = new Set<string>();
	for (const clientId of clientIds) {
		const stored = await adapter('Grant').findByOwner('clientId', clientId);
		for (const record of stored) {
			const grant = await Grant.fromStored(record);
			if (
				grant === undefined ||
				grant.isExpired ||
				(grant.payload.bucketId !== undefined &&
					grant.payload.bucketId !== bucketId) ||
				grant.payload.resources?.[identifier] === undefined ||
				grant.payload.accountId === undefined
			) {
				continue;
			}
			holders.add(grant.payload.accountId);
		}
	}
	return holders.size;
}

export async function apiSignInPreview(
	bucket: UserBucket,
	identifier: string,
	existing:
		| Pick<
				ProtectedResource,
				'requireCode' | 'requirePasskey' | 'signInEveryMinutes' | 'tools'
		  >
		| undefined,
	next: RequirementChange
): Promise<ApiSignInPreview | null> {
	const changes = changesOf(existing ?? {}, next);
	if (changes.length === 0) return null;
	const passkeyOn = changes.includes('apiRequirePasskeyOn');
	const codeOn = changes.includes('apiRequireCodeOn');
	const groups = audienceGroups(existing);
	const apps = await appsNeverMeetingIt(bucket._id);
	const holders =
		existing === undefined
			? 0
			: await holdersOf(identifier, apps.clientIds, bucket._id);

	const consequences: string[] = [];
	let expect: ApiSignInPreview['expect'];
	if (passkeyOn) {
		const { withoutPasskey, providerOnly } = await audiencePasskeyCounts(
			bucket,
			groups
		);
		consequences.push(
			withoutPasskey === 0
				? 'Everyone who may call this API has a confirmed passkey.'
				: `${people(withoutPasskey, 'who may call this API has', 'who may call this API have')} no confirmed passkey. They will be asked to create one, or to confirm the one they made, before they can connect.`
		);
		if (providerOnly > 0) {
			consequences.push(
				`${people(providerOnly, 'can', 'can')} sign in only through a provider and cannot create a passkey here. They can't connect.`
			);
		}
		expect = { withoutPasskey, providerOnly, holders };
	} else {
		const counts = await audienceCounts(bucket, groups);
		const withoutAuthenticator = codeOn ? counts.withoutAuthenticator : 0;
		const { providerOnly } = counts;
		const selfService = (await selfServiceState(bucket)) === 'on';
		if (codeOn) {
			consequences.push(
				withoutAuthenticator === 0
					? 'Everyone who may connect with a password has an authenticator app.'
					: selfService
						? `${people(withoutAuthenticator, 'who may connect with a password has', 'who may connect with a password have')} no authenticator app. They will be asked to set one up first.`
						: `${people(withoutAuthenticator, 'who may connect with a password has', 'who may connect with a password have')} no authenticator app, and this project does not let people set one up themselves. They can't connect.`
			);
			if (providerOnly > 0) {
				consequences.push(
					`${people(providerOnly, 'can', 'can')} sign in only through a provider. They can't connect.`
				);
			}
		}
		expect = { withoutAuthenticator, providerOnly, holders };
	}
	if (changes.includes('apiSignInEvery') && expect.providerOnly > 0) {
		consequences.push(
			`${people(expect.providerOnly, 'signs', 'sign')} in only through a provider. The provider is asked for a new sign-in, but FoxAuth can't confirm one happened.`
		);
	}
	if (holders > 0) {
		consequences.push(
			holders === 1
				? '1 person has an app connected to this API now. They will be asked to sign in again when their app next renews its connection, unless their sign-in already meets this.'
				: `${String(holders)} people have an app connected to this API now. They will be asked to sign in again when their app next renews its connection, unless their sign-in already meets this.`
		);
	}
	consequences.push(
		'Apps that connect by a client metadata document are not counted above.'
	);
	for (const name of apps.machineApps) {
		consequences.push(`${name} acts for no one and can't connect.`);
	}
	for (const name of apps.assertionApps) {
		consequences.push(
			`${name} signs in by assertion and can't connect that way.`
		);
	}
	return {
		consequences,
		expect,
		changes,
		machineApps: apps.machineApps,
		assertionApps: apps.assertionApps
	};
}
