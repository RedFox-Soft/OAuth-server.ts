import type {
	ErrorGroup,
	ErrorStoreQuery,
	ErrorRecord,
	ErrorSummaryBucket
} from '../adapters/types.js';

export const ERROR_PAGE_DEFAULT_LIMIT = 50;
export const ERROR_PAGE_MAX_LIMIT = 200;

/*
 * Paging, filtering, sample admission and summarisation for the error store, in one place because both
 * adapters must behave identically and a duplicated rule is exactly where the two drift apart. The
 * audit trail's helper module exists for the same reason and is worth reading alongside this one.
 *
 * Imports only types, so the MongoDB store can use it without dragging anything into the test-time
 * import graph.
 */
export function normalizeErrorPaging(query: ErrorStoreQuery = {}): {
	limit: number;
	offset: number;
} {
	// Clamped rather than refused: someone paging a large store should not get an error for asking for
	// too much.
	const requested = Math.trunc(query.limit ?? ERROR_PAGE_DEFAULT_LIMIT);
	return {
		limit: Math.min(Math.max(requested, 1), ERROR_PAGE_MAX_LIMIT),
		offset: Math.max(Math.trunc(query.offset ?? 0), 0)
	};
}

/*
 * Newest first by last-seen, with `_id` breaking ties. `_id` is unique, so the order is total — which
 * is what stops paging from dropping or repeating a group when two faults share a millisecond. That is
 * ordinary here rather than a corner case: a storm is one of the things this store exists to show.
 */
export function compareErrorGroups(a: ErrorGroup, b: ErrorGroup): number {
	const byTime = b.lastSeenAt.getTime() - a.lastSeenAt.getTime();
	if (byTime !== 0) {
		return byTime;
	}
	if (a._id === b._id) {
		return 0;
	}
	return a._id < b._id ? 1 : -1;
}

function matchesSample(sample: ErrorRecord, query: ErrorStoreQuery): boolean {
	if (query.clientId !== undefined && sample.clientId !== query.clientId) {
		return false;
	}
	// One filter, two arms, like the audit trail's: a reviewer reads emails, but a deleted admin's
	// records are findable only by id.
	if (
		query.actor !== undefined &&
		sample.actor?.id !== query.actor &&
		sample.actor?.email !== query.actor
	) {
		return false;
	}
	if (query.reference !== undefined && sample.reference !== query.reference) {
		return false;
	}
	return true;
}

/*
 * Whether a group matches. The sample-scoped filters (client, actor, reference) match if *any* retained
 * sample matches, because the group is the unit a reader works in: asking for one client's failures
 * means "faults this client has hit", not "faults only this client has ever hit".
 *
 * A consequence worth stating, because it is visible to an operator: the sample cap can make a
 * client-filtered result incomplete for a very noisy fault whose retained samples have all been
 * replaced. The occurrence count on such a group is still exact — it is the attribution of individual
 * occurrences that is bounded, not the tally.
 */
export function matchesErrorQuery(
	group: ErrorGroup,
	query: ErrorStoreQuery = {},
	now: Date = new Date()
): boolean {
	/*
	 * Expired groups are invisible even while physically present. MongoDB's TTL sweep is eventual and
	 * the memory store sweeps lazily, so neither adapter may rely on deletion having happened — without
	 * this, the two would answer differently for the same data purely on sweep timing.
	 */
	if (group.expiresAt <= now) {
		return false;
	}
	if (query.errorCode !== undefined && group.errorCode !== query.errorCode) {
		return false;
	}
	if (query.route !== undefined && group.route !== query.route) {
		return false;
	}
	if (query.surface !== undefined && group.surface !== query.surface) {
		return false;
	}
	if (query.status !== undefined && group.status !== query.status) {
		return false;
	}
	// Inclusive bounds on last-seen, each usable alone. Order between them is not policed here — a
	// backwards window is refused at the route, the only layer that can tell a caller why.
	if (query.from !== undefined && group.lastSeenAt < query.from) {
		return false;
	}
	if (query.to !== undefined && group.lastSeenAt > query.to) {
		return false;
	}

	const sampleScoped =
		query.clientId !== undefined ||
		query.actor !== undefined ||
		query.reference !== undefined;
	if (!sampleScoped) {
		return true;
	}
	return group.samples.some((sample) => matchesSample(sample, query));
}

/*
 * Admits one occurrence under the sample cap.
 *
 * The earliest sample is kept permanently and the rest are replaced most-recent-first, so a group that
 * has occurred a thousand times still shows where it started and what it is doing now. Keeping only
 * the newest would lose the first occurrence, which is usually the one that says what changed; keeping
 * only the oldest would make an ongoing fault look historical.
 */
export function admitSample(
	samples: readonly ErrorRecord[],
	incoming: ErrorRecord,
	cap: number
): ErrorRecord[] {
	const limit = Math.max(Math.trunc(cap), 1);
	const next = [...samples, incoming];
	if (next.length <= limit) {
		return next;
	}
	if (limit === 1) {
		// With room for one, the earliest is the one worth keeping: it is the only sample that can say
		// when the fault began, and `firstSeenAt` alone does not carry the request context.
		return [next[0]];
	}
	return [next[0], ...next.slice(next.length - (limit - 1))];
}

/*
 * Counts summed over occurrences rather than group rows: one fault seen 900 times must outrank nine
 * seen once, which is the whole point of the view. Most frequent first, ties broken by key so the
 * ordering is stable across calls and between adapters.
 */
export function summarizeBy(
	groups: readonly ErrorGroup[],
	keyOf: (group: ErrorGroup) => string
): ErrorSummaryBucket[] {
	const counts = new Map<string, number>();
	for (const group of groups) {
		const key = keyOf(group);
		counts.set(key, (counts.get(key) ?? 0) + group.occurrences);
	}
	return [...counts.entries()]
		.map(([key, count]) => ({ key, count }))
		.sort((a, b) =>
			b.count === a.count ? (a.key < b.key ? -1 : 1) : b.count - a.count
		);
}

export function totalOccurrences(groups: readonly ErrorGroup[]): number {
	return groups.reduce((sum, group) => sum + group.occurrences, 0);
}

/* When a group's retention window ends, given the moment it was last seen. */
export function expiryFrom(lastSeenAt: Date, retentionDays: number): Date {
	return new Date(lastSeenAt.getTime() + retentionDays * 24 * 60 * 60 * 1000);
}
