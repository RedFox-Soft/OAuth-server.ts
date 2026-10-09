/*
 * The `groups` scope and claim: the display names of the bucket groups an end user belongs to (specs/071).
 *
 * Built in, as `amr` is: the scope releases the claim whatever the claims setting holds, because a saved
 * setting replaces the default whole (lib/configs/application.ts), so a default entry would never reach a
 * deployment whose operator once saved it. The value is always computed from membership and never taken from
 * an account's stored claims (lib/addon/account.ts).
 *
 * Import-free, like every module in lib/consts.
 */

export const GROUPS_SCOPE = 'groups';
export const GROUPS_CLAIM = 'groups';

/*
 * Above this many groups a token carries an OpenID Connect distributed-claim reference to userinfo instead of
 * the list (Core §5.6.2), and userinfo carries the whole list. 200 is Entra ID's own JWT limit — the number
 * relying parties already code against. Fixed rather than a setting: nothing an operator would tune it for
 * outweighs a relying party knowing what to expect.
 */
export const GROUPS_TOKEN_LIMIT = 200;

/* The source name in `_claim_names`; there is one source, so the claim's own name serves. */
export const GROUPS_SOURCE = GROUPS_CLAIM;

type ClaimsEntry = null | readonly string[] | Readonly<Record<string, null>>;

// Array.isArray narrows a readonly array to any[]; this keeps its type.
const isList = (entry: ClaimsEntry): entry is readonly string[] =>
	Array.isArray(entry);

/*
 * The claims setting with the `groups` scope guaranteed to release the `groups` claim. Whatever the setting
 * says under `groups` is kept beside it, so an operator's own additions to the scope still apply.
 */
export function withGroupsScope(
	// Partial: a setting need not name the scope at all.
	claims: Readonly<Partial<Record<string, ClaimsEntry>>>
): Record<string, ClaimsEntry> {
	const existing = claims[GROUPS_SCOPE];
	let scope: ClaimsEntry;
	if (existing === undefined || existing === null) {
		scope = [GROUPS_CLAIM];
	} else if (isList(existing)) {
		scope = existing.includes(GROUPS_CLAIM)
			? existing
			: [...existing, GROUPS_CLAIM];
	} else {
		scope = { ...existing, [GROUPS_CLAIM]: null };
	}
	return { ...claims, [GROUPS_SCOPE]: scope };
}

/* The recorded snapshot as response members — for the JWT format and for introspection alike. */
export function groupsMembersOf(payload: {
	groups?: unknown;
	groupsSource?: unknown;
}): Record<string, unknown> {
	if (Array.isArray(payload.groups)) return { [GROUPS_CLAIM]: payload.groups };
	if (typeof payload.groupsSource === 'string') {
		return {
			_claim_names: { [GROUPS_CLAIM]: GROUPS_SOURCE },
			_claim_sources: { [GROUPS_SOURCE]: { endpoint: payload.groupsSource } }
		};
	}
	return {};
}
