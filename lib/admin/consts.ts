export const ADMIN_PROJECT_ID = 'admin';
export const ADMIN_BUCKET_ID = 'admin';
/*
 * The bucket a request reaches when nothing else routes it. Named here rather than repeated as a
 * literal because it is now load-bearing in a second way: it is the one bucket addressed at the bare
 * paths, so it is the one bucket whose issuer is the server's own.
 */
export const DEFAULT_BUCKET_ID = 'redfox';

/*
 * The two buckets served at the root, and therefore the two whose issuer is the instance's own.
 *
 * It lives here, in a module that imports nothing, because three very different places need the same
 * answer: `issuerFor`, which stamps `iss` into every token; `isAddressable`, which decides whether a
 * prefixed address resolves; and the console, whose browser bundle can reach no module that touches
 * the configuration layer. Each of them once knew this rule in its own words, and each pair that
 * disagreed produced a defect — the routing side and the issuing side disagreeing made a genuine
 * sign-in mint a token no client would accept, and the console disagreeing with both printed `/default`
 * as an address an operator could integrate against, which answers 404.
 *
 * The default bucket is the obvious member. The administrators bucket is the one that is not: the
 * console is a relying party on the instance's own issuer, so a token minted for that population must
 * carry it. Both hold a slug regardless, because a session cookie has to be named after something — a
 * slug is a name, not an address, and this predicate is the only thing that decides which buckets have
 * one.
 */
const SERVED_AT_THE_ROOT: ReadonlySet<string> = new Set([
	DEFAULT_BUCKET_ID,
	ADMIN_BUCKET_ID
]);

export function isServedAtTheRoot(bucketId: string): boolean {
	return SERVED_AT_THE_ROOT.has(bucketId);
}

/*
 * The group that owns containers no administrator owns. Reachable only by super administrators, and
 * exempt from the at-least-one-owner rule for the same reason the reserved admin project and bucket
 * are exempt from the group model: it is a holding area, not a tenant.
 *
 * Real rather than defensive — a super administrator can create a project with no owner, so
 * containers in exactly this state already exist. It outlived the ownership migration that first
 * populated it, which is why this no longer says "at migration time": the group is how an unowned
 * container is reached, not residue of a one-off rewrite.
 */
export const UNASSIGNED_GROUP_ID = 'unassigned';
/*
 * What the console calls that group. Held here rather than only in the two seeds because the console
 * labels a system group from this constant too: a database seeded before the name changed keeps its
 * stored "Unassigned" until db:setup runs again, and the operator should not see the older name in the
 * meantime. The id stays `unassigned` — renaming it would be a data migration for no visible gain.
 */
export const SYSTEM_GROUP_NAME = 'System';
export const ADMIN_CLIENT_ID = 'admin-panel';
export const ADMIN_SESSION_COOKIE = '_admin_session';

export const ADMIN_SESSION_TTL_SECONDS = 60 * 60; // sliding
export const ADMIN_SESSION_ABSOLUTE_TTL_SECONDS = 60 * 60 * 12; // hard cap
