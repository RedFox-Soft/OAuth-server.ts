import type { SQL } from 'bun';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type {
	ErrorGroup,
	ErrorGroupPage,
	ErrorOccurrence,
	ErrorPurgeEstimate,
	ErrorRecord,
	ErrorStoreBounds,
	ErrorStoreInstance,
	ErrorStoreQuery,
	ErrorSummary
} from '../types.js';
import {
	admitSample,
	expiryFrom,
	normalizeErrorPaging,
	summarizeBy,
	totalOccurrences
} from '../../helpers/error_store_query.js';
import nanoid from '../../helpers/nanoid.js';

const GROUP_DATES = ['firstSeenAt', 'lastSeenAt', 'expiresAt'] as const;
const SAMPLE_DATES = ['at'] as const;

/* A unique-violation, which here means only one thing: two instances recorded the same new fault in
 * the same instant and the fingerprint index refused the second. */
const UNIQUE_VIOLATION = '23505';

function isUniqueViolation(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		(error as { code?: unknown }).code === UNIQUE_VIOLATION
	);
}

/*
 * A sample-scoped clause. `samples.clientId` in MongoDB matches a group any of whose retained samples
 * names that client; in jsonb that is containment of a one-key object against the array, which says
 * the same thing and needs the GIN-free `@>` on the samples array.
 */
function sampleContains(handle: SQL, shape: Record<string, unknown>) {
	return handle`doc->'samples' @> ${[shape]}`;
}

/*
 * Builds the WHERE clause.
 *
 * The expiry bound is not housekeeping. The sweeper is eventual, so a group past its window can still
 * be on disk, and the memory store filters the same way — without this the adapters would answer
 * differently for identical data purely on sweep timing. It reads the `expires_at` column rather than
 * the document field so the partial index can serve it.
 *
 * `lastSeenAt` is compared as text for the same reason the audit store's timestamp is: the declared
 * index is over `(doc->>'lastSeenAt')`, and ISO-8601 in UTC sorts lexicographically the way it sorts
 * chronologically. A cast would be correct and would quietly stop using the index.
 */
function conditionsFor(handle: SQL, query: ErrorStoreQuery) {
	let where = handle`expires_at > now()`;
	const and = (fragment: typeof where) => {
		where = handle`${where} AND ${fragment}`;
	};

	if (query.errorCode !== undefined) {
		and(handle`doc->>'errorCode' = ${query.errorCode}`);
	}
	if (query.route !== undefined) {
		and(handle`doc->>'route' = ${query.route}`);
	}
	if (query.surface !== undefined) {
		and(handle`doc->>'surface' = ${query.surface}`);
	}
	if (query.status !== undefined) {
		and(handle`(doc->>'status')::int = ${query.status}`);
	}
	if (query.clientId !== undefined) {
		and(sampleContains(handle, { clientId: query.clientId }));
	}
	if (query.reference !== undefined) {
		and(sampleContains(handle, { reference: query.reference }));
	}
	// One filter, two arms, so a deleted administrator's records stay findable by id.
	if (query.actor !== undefined) {
		and(
			handle`(${sampleContains(handle, { actor: { id: query.actor } })} OR ${sampleContains(
				handle,
				{ actor: { email: query.actor } }
			)})`
		);
	}
	// Inclusive both ends, matching the other adapters. Order between the bounds is not policed here —
	// the route refuses a backwards window, where the caller can be told why.
	if (query.from !== undefined) {
		and(handle`doc->>'lastSeenAt' >= ${query.from.toISOString()}`);
	}
	if (query.to !== undefined) {
		and(handle`doc->>'lastSeenAt' <= ${query.to.toISOString()}`);
	}

	return where;
}

/*
 * Recorded internal server faults, one row per distinct fault with its occurrences embedded.
 *
 * No update path is exposed for a stored sample: `record` advances a group's own bookkeeping — count,
 * last-seen, expiry, admitted samples — and nothing edits what a past occurrence said.
 */
export class ErrorStore implements ErrorStoreInstance {
	private area: string = STORE_AREAS.errorStore;

	/*
	 * Evicts until a new group fits. Least *recently seen*, never oldest-created: a fault that started
	 * last month and is still happening outranks one that happened once this morning. Served by the
	 * declared `{ lastSeenAt, _id }` index, so this is a one-row lookup rather than a scan.
	 */
	private async evictTo(max: number): Promise<void> {
		const handle = sql();
		const limit = Math.max(Math.trunc(max), 1);

		for (;;) {
			const counted = await handle`
				SELECT count(*)::int AS held FROM ${handle(this.area)}
			`;
			const held = Number(
				(counted[0] as { held?: number } | undefined)?.held ?? 0
			);
			if (held < limit) return;

			const removed = await handle`
				DELETE FROM ${handle(this.area)} WHERE id = (
					SELECT id FROM ${handle(this.area)}
					ORDER BY doc->>'lastSeenAt' ASC, id ASC
					LIMIT 1
				)
				RETURNING id
			`;
			if (removed.length === 0) return;
		}
	}

	async record(
		occurrence: ErrorOccurrence,
		bounds: ErrorStoreBounds
	): Promise<ErrorGroup | undefined> {
		const handle = sql();
		const now = new Date();
		const expiresAt = expiryFrom(now, bounds.retentionDays);

		const found = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'fingerprint' = ${occurrence.fingerprint}
		`;
		const existing = this.groupOf(found[0]);

		if (existing) {
			const samples = admitSample(
				existing.samples,
				occurrence.record,
				bounds.samplesPerGroup
			);
			/*
			 * The newest occurrence's message and origin win. Two occurrences sharing a fingerprint arose
			 * at the same place, so this only refreshes an interpolated detail — and the newest is the one
			 * an operator is about to act on.
			 */
			const patch = {
				occurrences: existing.occurrences + 1,
				lastSeenAt: now,
				expiresAt,
				samples,
				message: occurrence.message,
				origin: occurrence.origin
			};

			await handle`
				UPDATE ${handle(this.area)}
				SET doc = doc || ${patch}, expires_at = ${expiresAt}
				WHERE id = ${existing._id}
			`;

			return { ...existing, ...patch };
		}

		await this.evictTo(bounds.maxGroups);

		const group: ErrorGroup = {
			_id: nanoid(),
			fingerprint: occurrence.fingerprint,
			errorCode: occurrence.errorCode,
			status: occurrence.status,
			surface: occurrence.surface,
			route: occurrence.route,
			method: occurrence.method,
			origin: occurrence.origin,
			message: occurrence.message,
			occurrences: 1,
			firstSeenAt: now,
			lastSeenAt: now,
			expiresAt,
			samples: [occurrence.record]
		};

		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${group._id}, ${group}, ${expiresAt})
			`;
			return group;
		} catch (error) {
			/*
			 * Two instances recording the same new fault in the same instant: the unique fingerprint index
			 * refuses the second insert. Counting the occurrence against the winner is the correct outcome,
			 * and losing the race is not an error worth surfacing — the fault is recorded either way.
			 * Recursing once cannot loop, because the group now exists and the branch above takes it.
			 *
			 * Narrowed to the unique violation, unlike the MongoDB store's bare catch: a connection failure
			 * here would otherwise recurse into the same failure instead of surfacing.
			 */
			if (!isUniqueViolation(error)) throw error;
			return this.record(occurrence, bounds);
		}
	}

	async list(query: ErrorStoreQuery = {}): Promise<ErrorGroupPage> {
		const handle = sql();
		const where = conditionsFor(handle, query);
		const { limit, offset } = normalizeErrorPaging(query);

		/*
		 * `id` descending after `lastSeenAt` makes the order total, so a page boundary cannot drop or
		 * repeat a group when two faults share a millisecond — which a storm makes ordinary.
		 */
		const [rows, counted] = await Promise.all([
			handle`
				SELECT doc FROM ${handle(this.area)}
				WHERE ${where}
				ORDER BY doc->>'lastSeenAt' DESC, id DESC
				LIMIT ${limit} OFFSET ${offset}
			`,
			handle`
				SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${where}
			`
		]);

		// `dropped` is filled in by the route from the queue, which owns the counter; the store cannot
		// know it.
		return {
			groups: this.groupsOf(rows),
			total: Number((counted[0] as { total?: number } | undefined)?.total ?? 0),
			dropped: 0
		};
	}

	async get(id: string): Promise<ErrorGroup | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${id} AND expires_at > now()
		`;
		return this.groupOf(rows[0]) ?? undefined;
	}

	async findByReference(
		reference: string
	): Promise<{ group: ErrorGroup; sample: ErrorRecord } | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE ${sampleContains(handle, { reference })} AND expires_at > now()
			LIMIT 1
		`;
		const group = this.groupOf(rows[0]);
		if (!group) return undefined;

		const sample = group.samples.find(
			(candidate) => candidate.reference === reference
		);
		// The index matched the row, so the sample is present; the guard keeps the return type honest
		// rather than asserting it away.
		return sample ? { group, sample } : undefined;
	}

	async summarize(query: ErrorStoreQuery = {}): Promise<ErrorSummary> {
		const handle = sql();
		const where = conditionsFor(handle, query);

		/*
		 * Projected without `samples`, which is the whole weight of a row, then summed through the shared
		 * helper. Grouping in SQL would push the work into the server and would also be a second
		 * definition of "most frequent first, ties broken by key" — and the adapters agreeing on that
		 * ordering matters more here than the round trip does at a four-figure group cap.
		 */
		const rows = await handle`
			SELECT (doc - 'samples') AS doc FROM ${handle(this.area)} WHERE ${where}
		`;
		const groups = this.groupsOf(rows);

		return {
			total: totalOccurrences(groups),
			byErrorCode: summarizeBy(groups, (group) => group.errorCode),
			byRoute: summarizeBy(groups, (group) => group.route),
			dropped: 0
		};
	}

	async previewPurge(query: ErrorStoreQuery): Promise<ErrorPurgeEstimate> {
		const handle = sql();
		const where = conditionsFor(handle, query);
		const rows = await handle`
			SELECT (doc - 'samples') AS doc FROM ${handle(this.area)} WHERE ${where}
		`;
		const groups = this.groupsOf(rows);

		return { groups: groups.length, occurrences: totalOccurrences(groups) };
	}

	async purge(query: ErrorStoreQuery): Promise<number> {
		const handle = sql();
		const where = conditionsFor(handle, query);
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE ${where} RETURNING id
		`;
		return rows.length;
	}

	/*
	 * Revives the group's own dates and each retained sample's `at`. `reviveDates` reaches top-level
	 * keys only, and a sample's timestamp is one level down — missing it would leave every occurrence
	 * carrying a string where the console renders a time.
	 */
	private groupOf(row: unknown): ErrorGroup | null {
		const doc = docOf<ErrorGroup>(row);
		if (doc === undefined) return null;

		const group = reviveDates(doc, GROUP_DATES);
		return group.samples === undefined
			? group
			: {
					...group,
					samples: group.samples.map((sample) =>
						reviveDates(sample, SAMPLE_DATES)
					)
				};
	}

	private groupsOf(rows: unknown[]): ErrorGroup[] {
		return rows
			.map((row) => this.groupOf(row))
			.filter((group): group is ErrorGroup => group !== null);
	}
}
