import type { AdminAuditEntry, AdminAuditQuery } from '../adapters/types.js';

export const AUDIT_PAGE_DEFAULT_LIMIT = 50;
export const AUDIT_PAGE_MAX_LIMIT = 200;

/*
 * Paging, filtering and read-side defaults for the admin audit trail, in one place because both
 * adapters must behave identically (FR-017) and a duplicated clamp is exactly where the two would
 * drift apart — the way `revokeByGrantId` and email lowercasing already have.
 *
 * Imports only types, so the MongoDB store can use it without dragging anything into the test-time
 * import graph.
 */
export function normalizeAuditPaging(query: AdminAuditQuery = {}): {
	limit: number;
	offset: number;
} {
	// A caller asking for more than the maximum is clamped rather than refused: someone paging a large
	// trail should not get an error for asking for too much.
	const requested = Math.trunc(query.limit ?? AUDIT_PAGE_DEFAULT_LIMIT);
	return {
		limit: Math.min(Math.max(requested, 1), AUDIT_PAGE_MAX_LIMIT),
		offset: Math.max(Math.trunc(query.offset ?? 0), 0)
	};
}

/*
 * Newest first, with `_id` breaking ties. `_id` is unique, so the order is total — which is what stops
 * paging from dropping or repeating an entry when two actions share a timestamp. Ordinal string
 * comparison matches MongoDB's binary comparison for the ASCII identifiers in use.
 */
export function compareAuditEntries(
	a: AdminAuditEntry,
	b: AdminAuditEntry
): number {
	const byTime = b.timestamp.getTime() - a.timestamp.getTime();
	if (byTime !== 0) {
		return byTime;
	}
	if (a._id === b._id) {
		return 0;
	}
	return a._id < b._id ? 1 : -1;
}

export function matchesAuditQuery(
	entry: AdminAuditEntry,
	query: AdminAuditQuery = {}
): boolean {
	// One filter, two arms: a reviewer reads emails in the UI, but a deleted admin's entries are
	// findable only by id.
	if (
		query.actor !== undefined &&
		entry.actorId !== query.actor &&
		entry.actorEmail !== query.actor
	) {
		return false;
	}
	if (query.action !== undefined && entry.action !== query.action) {
		return false;
	}
	if (query.targetType !== undefined && entry.targetType !== query.targetType) {
		return false;
	}
	if (query.targetId !== undefined && entry.targetId !== query.targetId) {
		return false;
	}
	if (
		query.targetScope !== undefined &&
		entry.targetScope !== query.targetScope
	) {
		return false;
	}
	/*
	 * A console entry stores no surface at all, so 'console' cannot be an equality match — it is the
	 * absence. Written as a translation rather than a comparison because the alternative was to
	 * backfill every historical entry, and the trail is append-only.
	 */
	if (query.viaSurface !== undefined) {
		const surface = entry.viaSurface ?? 'console';
		if (surface !== query.viaSurface) {
			return false;
		}
	}
	if (
		query.viaClientId !== undefined &&
		entry.viaClientId !== query.viaClientId
	) {
		return false;
	}
	// Inclusive bounds, each usable alone. Order between them is not policed here — a backwards window
	// is refused at the route, which is the only layer that can tell a caller why.
	if (query.from !== undefined && entry.timestamp < query.from) {
		return false;
	}
	if (query.to !== undefined && entry.timestamp > query.to) {
		return false;
	}
	return true;
}

/*
 * Read-side defaults for the two fields added after entries were already being written. Absent means
 * "nothing to say", identical to an entry from before the field existed — which is what makes the
 * absence free of a migration. Backfilling would mean writing to records the constitution declares
 * immutable.
 */
export function withAuditDefaults(entry: AdminAuditEntry): AdminAuditEntry {
	return {
		...entry,
		targetScope: entry.targetScope ?? null,
		attributes: entry.attributes ?? []
	};
}
