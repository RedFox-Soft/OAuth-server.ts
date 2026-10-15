/*
 * The words the admin plane speaks (specs/100), against the names storage keeps.
 *
 * A bucket is shown as a project, an administrator group as a team, and a bucket group as a group of end
 * users. Storage keeps its names, so where stored text reaches the edge verbatim it is translated here.
 * That stored text is the audit trail's action ids, target types, attribute names and cascade keys.
 *
 * The trail is evidence and is never rewritten, so translation is the only way its history reads in
 * today's words. It also keeps history truthful. The `project.*` ids already stored name the entity spec
 * 099 removed, a different thing from today's project, so they are shown as a retired project. Writing
 * today's actions as `project.*` would have merged the two.
 *
 * Import-free on purpose: the MCP catalogue and the docs export read it, and neither may reach a module
 * that touches storage.
 */

/* First segment of an action id, stored → edge. A bijection, so a filter can be mapped back exactly. */
const ACTION_SEGMENTS: ReadonlyMap<string, string> = new Map([
	['bucket', 'project'],
	['bucketgroup', 'group'],
	['group', 'team'],
	['project', 'retiredproject']
]);

const TARGET_TYPES: ReadonlyMap<string, string> = new Map([
	['UserBucket', 'Project'],
	['Group', 'Team'],
	['BucketGroup', 'Group'],
	['Project', 'RetiredProject']
]);

const ATTRIBUTES: ReadonlyMap<string, string> = new Map([
	['ownerGroupId', 'ownerTeamId'],
	['buckets.reservedHostnames', 'projects.reservedHostnames']
]);

/* `projects` is only ever the count a bucket move carried before spec 099 removed them. */
const CASCADE_KEYS: ReadonlyMap<string, string> = new Map([
	['projects', 'retiredProjects']
]);

function inverse(
	map: ReadonlyMap<string, string>
): ReadonlyMap<string, string> {
	return new Map([...map].map(([stored, edge]) => [edge, stored]));
}

const STORED_SEGMENT = inverse(ACTION_SEGMENTS);
const STORED_TARGET_TYPE = inverse(TARGET_TYPES);

function splitFirst(action: string): [string, string] {
	const dot = action.indexOf('.');
	return dot < 0 ? [action, ''] : [action.slice(0, dot), action.slice(dot)];
}

export function edgeAction(stored: string): string {
	const [first, rest] = splitFirst(stored);
	return (ACTION_SEGMENTS.get(first) ?? first) + rest;
}

/*
 * The stored id an edge action names, or null when it names none. A stored-only segment
 * (`bucket.create`) is not an edge name: it names nothing, rather than reaching the stored entries it
 * once meant.
 */
export function storedAction(edge: string): string | null {
	const [first, rest] = splitFirst(edge);
	const stored = STORED_SEGMENT.get(first);
	if (stored !== undefined) return stored + rest;
	return ACTION_SEGMENTS.has(first) ? null : edge;
}

/*
 * The stored prefix an edge prefix selects, null when it selects nothing, or 'ambiguous' when it stops
 * inside a translated first segment. In that last case, edge `p` would have to select both stored
 * `bucket.` and `provisioning.`, which one stored prefix cannot express. A complete first segment
 * selects only that segment: edge `project` must not reach stored `bucketgroup.*` through the stored
 * prefix `bucket`.
 */
export function storedActionPrefix(
	edge: string
): { prefix: string } | null | 'ambiguous' {
	if (edge.includes('.')) {
		const stored = storedAction(edge);
		return stored === null ? null : { prefix: stored };
	}
	const stored = STORED_SEGMENT.get(edge);
	if (stored !== undefined) return { prefix: `${stored}.` };
	if (ACTION_SEGMENTS.has(edge)) return null;
	const translated = [...ACTION_SEGMENTS.keys(), ...STORED_SEGMENT.keys()];
	return translated.some((segment) => segment.startsWith(edge))
		? 'ambiguous'
		: { prefix: edge };
}

export function edgeTargetType(stored: string): string {
	return TARGET_TYPES.get(stored) ?? stored;
}

export function storedTargetType(edge: string): string | null {
	const stored = STORED_TARGET_TYPE.get(edge);
	if (stored !== undefined) return stored;
	return TARGET_TYPES.has(edge) ? null : edge;
}

export function edgeAuditAttribute(stored: string): string {
	return ATTRIBUTES.get(stored) ?? stored;
}

export function edgeCascade(
	cascade: Readonly<Record<string, number>>
): Record<string, number> {
	return Object.fromEntries(
		Object.entries(cascade).map(([key, count]) => [
			CASCADE_KEYS.get(key) ?? key,
			count
		])
	);
}
