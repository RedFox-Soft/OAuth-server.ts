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
	compareErrorGroups,
	expiryFrom,
	matchesErrorQuery,
	normalizeErrorPaging,
	summarizeBy,
	totalOccurrences
} from '../../helpers/error_store_query.js';
import nanoid from '../../helpers/nanoid.js';

/*
 * In-memory record of internal server faults, grouped by fingerprint.
 *
 * Unlike the admin audit store this one is not append-only — a purge removes, and the caps evict — but
 * an individual occurrence is still immutable once written: nothing here edits a stored sample, and the
 * interface offers no way to.
 */
export class ErrorStore implements ErrorStoreInstance {
	private groups = new Map<string, ErrorGroup>();

	/*
	 * Copied on the way out, like the audit store's reads: a caller holding a live reference into a
	 * group could rewrite what the store says happened, which is the one thing a record of faults must
	 * make impossible. The samples array is rebuilt rather than shared for the same reason.
	 */
	private clone(group: ErrorGroup): ErrorGroup {
		return {
			...group,
			origin: { ...group.origin },
			samples: group.samples.map((sample) => ({
				...sample,
				actor: sample.actor ? { ...sample.actor } : null,
				submittedFields: [...sample.submittedFields]
			}))
		};
	}

	/*
	 * Drops what the retention window has passed. Lazy — on read and on write — rather than on a timer:
	 * a timer in the memory adapter would keep the test process alive and fire between unrelated specs.
	 *
	 * Reads additionally filter on expiry through matchesErrorQuery, so an answer never depends on
	 * whether this has run. That is deliberate duplication: MongoDB's TTL sweep is eventual, and both
	 * adapters must agree regardless of sweep timing.
	 */
	private sweep(now: Date): void {
		for (const [id, group] of this.groups) {
			if (group.expiresAt <= now) {
				this.groups.delete(id);
			}
		}
	}

	private live(query: ErrorStoreQuery, now: Date): ErrorGroup[] {
		return [...this.groups.values()].filter((group) =>
			matchesErrorQuery(group, query, now)
		);
	}

	/*
	 * Evicts until a new group would fit. Least *recently seen*, never oldest-created: a fault that
	 * started last month and is still happening outranks one that happened once this morning, and
	 * creation order would discard exactly the wrong one.
	 */
	private evictTo(max: number): void {
		const limit = Math.max(Math.trunc(max), 1);
		while (this.groups.size >= limit) {
			let oldest: ErrorGroup | undefined;
			for (const group of this.groups.values()) {
				if (!oldest || group.lastSeenAt < oldest.lastSeenAt) {
					oldest = group;
				}
			}
			if (!oldest) {
				return;
			}
			this.groups.delete(oldest._id);
		}
	}

	async record(
		occurrence: ErrorOccurrence,
		bounds: ErrorStoreBounds
	): Promise<ErrorGroup | undefined> {
		const now = new Date();
		this.sweep(now);

		const existing = [...this.groups.values()].find(
			(group) => group.fingerprint === occurrence.fingerprint
		);

		if (existing) {
			existing.occurrences += 1;
			existing.lastSeenAt = now;
			existing.expiresAt = expiryFrom(now, bounds.retentionDays);
			existing.samples = admitSample(
				existing.samples,
				occurrence.record,
				bounds.samplesPerGroup
			);
			/*
			 * The message and origin of the newest occurrence win. Two occurrences sharing a fingerprint
			 * arose at the same place, so this only ever refreshes an interpolated detail — and the newest
			 * is the one an operator is about to act on.
			 */
			existing.message = occurrence.message;
			existing.origin = occurrence.origin;
			return this.clone(existing);
		}

		this.evictTo(bounds.maxGroups);

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
			expiresAt: expiryFrom(now, bounds.retentionDays),
			samples: [occurrence.record]
		};
		this.groups.set(group._id, group);
		return this.clone(group);
	}

	async list(query: ErrorStoreQuery = {}): Promise<ErrorGroupPage> {
		const now = new Date();
		this.sweep(now);
		const matched = this.live(query, now);
		const { limit, offset } = normalizeErrorPaging(query);

		return {
			// Sorted on a copy: sorting the backing collection in place would destroy nothing here, but
			// the ordering is derived from the data rather than from insertion, and keeping that true of
			// both adapters is what makes the total order a property instead of a coincidence.
			groups: [...matched]
				.sort(compareErrorGroups)
				.slice(offset, offset + limit)
				.map((group) => this.clone(group)),
			total: matched.length,
			// Filled in by the route from the queue, which owns the counter; the store cannot know it.
			dropped: 0
		};
	}

	async get(id: string): Promise<ErrorGroup | undefined> {
		const now = new Date();
		this.sweep(now);
		const group = this.groups.get(id);
		if (!group || !matchesErrorQuery(group, {}, now)) {
			return undefined;
		}
		return this.clone(group);
	}

	async findByReference(
		reference: string
	): Promise<{ group: ErrorGroup; sample: ErrorRecord } | undefined> {
		const now = new Date();
		this.sweep(now);

		for (const group of this.groups.values()) {
			if (!matchesErrorQuery(group, {}, now)) {
				continue;
			}
			const index = group.samples.findIndex(
				(candidate) => candidate.reference === reference
			);
			if (index !== -1) {
				const copy = this.clone(group);
				// Taken from the copy by position, so the returned sample is not a live reference either —
				// and by position rather than by a second search, which would need an assertion to prove it
				// found what the first one already did.
				return { group: copy, sample: copy.samples[index] };
			}
		}
		return undefined;
	}

	async summarize(query: ErrorStoreQuery = {}): Promise<ErrorSummary> {
		const now = new Date();
		this.sweep(now);
		const matched = this.live(query, now);

		return {
			total: totalOccurrences(matched),
			byErrorCode: summarizeBy(matched, (group) => group.errorCode),
			byRoute: summarizeBy(matched, (group) => group.route),
			dropped: 0
		};
	}

	async previewPurge(query: ErrorStoreQuery): Promise<ErrorPurgeEstimate> {
		const now = new Date();
		this.sweep(now);
		const matched = this.live(query, now);

		return {
			groups: matched.length,
			occurrences: totalOccurrences(matched)
		};
	}

	async purge(query: ErrorStoreQuery): Promise<number> {
		const now = new Date();
		this.sweep(now);
		const matched = this.live(query, now);

		for (const group of matched) {
			this.groups.delete(group._id);
		}
		return matched.length;
	}
}
