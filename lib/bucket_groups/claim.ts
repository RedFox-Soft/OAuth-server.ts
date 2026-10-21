import { getBucketGroupStore, getGroupStore } from '../adapters/index.js';
import { MAX_END_USER_PAGE } from '../adapters/types.js';
import {
	GROUPS_CLAIM,
	GROUPS_SCOPE,
	GROUPS_SOURCE,
	GROUPS_TOKEN_LIMIT
} from '../consts/groups_claim.js';

/*
 * The `groups` claim for one user: the sorted display names of their bucket groups; nothing when they are in
 * none; and, where the response has a size limit (a token), an OpenID Connect distributed-claim reference to
 * userinfo once there are more than GROUPS_TOKEN_LIMIT of them (Core §5.6.2). Userinfo has no such limit and
 * always gets the list.
 */
export type GroupsClaim =
	| { kind: 'none' }
	| { kind: 'list'; names: string[] }
	| {
			kind: 'reference';
			claimNames: Record<string, string>;
			claimSources: Record<string, { endpoint: string }>;
	  };

export async function groupsClaimFor(
	bucketId: string,
	userId: string,
	options: { reference: boolean; userinfoEndpoint: string }
): Promise<GroupsClaim> {
	const store = getBucketGroupStore();
	const ids = (await store.groupIdsOf(bucketId, [userId])).get(userId) ?? [];
	if (ids.length === 0) return { kind: 'none' };
	if (options.reference && ids.length > GROUPS_TOKEN_LIMIT) {
		return {
			kind: 'reference',
			claimNames: { [GROUPS_CLAIM]: GROUPS_SOURCE },
			claimSources: { [GROUPS_SOURCE]: { endpoint: options.userinfoEndpoint } }
		};
	}
	const names: string[] = [];
	for (let i = 0; i < ids.length; i += MAX_END_USER_PAGE) {
		names.push(
			...(await store.findMany(ids.slice(i, i + MAX_END_USER_PAGE))).map(
				(g) => g.displayName
			)
		);
	}
	return { kind: 'list', names: names.sort() };
}

/*
 * The `groups` claim for an administrator (specs/109): the names of the teams they are a member of, so an
 * internal tool registered in the administrators' bucket can admit them by team. Their personal team is left
 * out — nobody else can be in it, so no tool could gate on it. The same shape and the same reference rule as a
 * project's groups, so a relying party reads both alike.
 *
 * A read of names into a signed response and nothing more: teams are still changed only by the team routes,
 * and nothing a relying party sends back reaches them — the separation spec 071 made teams a different entity
 * from the groups SCIM writes for.
 */
export async function administratorTeamsClaimFor(
	userId: string,
	options: { reference: boolean; userinfoEndpoint: string }
): Promise<GroupsClaim> {
	const names = (await getGroupStore().listByMember(userId))
		.filter((team) => team.kind !== 'personal')
		.map((team) => team.name)
		.sort();
	if (names.length === 0) return { kind: 'none' };
	if (options.reference && names.length > GROUPS_TOKEN_LIMIT) {
		return {
			kind: 'reference',
			claimNames: { [GROUPS_CLAIM]: GROUPS_SOURCE },
			claimSources: { [GROUPS_SOURCE]: { endpoint: options.userinfoEndpoint } }
		};
	}
	return { kind: 'list', names };
}

/*
 * What a resource-bound access token records about the user's groups when the authorization granted the
 * `groups` scope (RFC 9068 §2.2.3.1): the list, or — above the limit — where to fetch it. A snapshot taken at
 * issue, so the JWT and introspection of the same token always agree, and a change of membership shows in
 * the next token rather than in a live one.
 *
 * The condition is the granted OIDC scope, not the token's own `scope`: a resource-bound token carries only
 * the resource's scopes, while the user's consent to release their groups was given to the client asking for
 * this token.
 */
export async function resourceTokenGroups(
	grantedOidcScope: string,
	bucketId: string | undefined,
	accountId: string | undefined,
	userinfoEndpoint: string
): Promise<{ groups?: string[]; groupsSource?: string }> {
	if (!bucketId || !accountId) return {};
	if (!grantedOidcScope.split(' ').includes(GROUPS_SCOPE)) return {};
	const claim = await groupsClaimFor(bucketId, accountId, {
		reference: true,
		userinfoEndpoint
	});
	if (claim.kind === 'list') return { groups: claim.names };
	if (claim.kind === 'reference') return { groupsSource: userinfoEndpoint };
	return {};
}
