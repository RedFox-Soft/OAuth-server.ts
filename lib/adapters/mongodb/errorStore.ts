import type { Filter } from 'mongodb';
import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
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

/*
 * Translates a query into a filter document. Every clause is an exact match except the time window,
 * and the sample-scoped clauses reach into the embedded array — `samples.clientId` matches a group any
 * of whose retained samples names that client, which is the same "any retained sample" rule
 * matchesErrorQuery applies in the memory store.
 *
 * The expiry clause is not housekeeping: MongoDB's TTL sweep is eventual, so a group past its window
 * can still be on disk, and the memory store filters the same way. Without this the two adapters would
 * answer differently for identical data purely on sweep timing.
 */
function toFilter(query: ErrorStoreQuery, now: Date): Filter<ErrorGroup> {
	const filter: Filter<ErrorGroup> = { expiresAt: { $gt: now } };

	if (query.errorCode !== undefined) {
		filter.errorCode = query.errorCode;
	}
	if (query.route !== undefined) {
		filter.route = query.route;
	}
	if (query.surface !== undefined) {
		filter.surface = query.surface as ErrorGroup['surface'];
	}
	if (query.status !== undefined) {
		filter.status = query.status;
	}
	if (query.clientId !== undefined) {
		filter['samples.clientId'] = query.clientId;
	}
	if (query.reference !== undefined) {
		filter['samples.reference'] = query.reference;
	}
	// One filter, two arms, so a deleted administrator's records stay findable by id.
	if (query.actor !== undefined) {
		filter.$or = [
			{ 'samples.actor.id': query.actor },
			{ 'samples.actor.email': query.actor }
		];
	}
	if (query.from !== undefined || query.to !== undefined) {
		// Inclusive both ends, matching the memory adapter. Order between the bounds is not policed here
		// — the route refuses a backwards window, where the caller can be told why.
		filter.lastSeenAt = {
			...(query.from === undefined ? {} : { $gte: query.from }),
			...(query.to === undefined ? {} : { $lte: query.to })
		};
	}
	return filter;
}

/*
 * MongoDB record of internal server faults (collection `errorStore`), one document per distinct fault
 * with its occurrences embedded.
 *
 * No update path is exposed for a stored sample: `record` advances a group's own bookkeeping — count,
 * last-seen, expiry, admitted samples — and nothing edits what a past occurrence said.
 */
export class ErrorStore implements ErrorStoreInstance {
	private collection = db.collection<ErrorGroup>(STORE_AREAS.errorStore);

	/*
	 * Evicts until a new group fits. Least *recently seen*, never oldest-created: a fault that started
	 * last month and is still happening outranks one that happened once this morning. Served by the
	 * `{ lastSeenAt, _id }` index, so this is a one-document lookup rather than a scan.
	 */
	private async evictTo(max: number): Promise<void> {
		const limit = Math.max(Math.trunc(max), 1);
		for (;;) {
			const count = await this.collection.countDocuments();
			if (count < limit) {
				return;
			}
			const oldest = await this.collection
				.find({}, { projection: { _id: 1 } })
				.sort({ lastSeenAt: 1, _id: 1 })
				.limit(1)
				.next();
			if (!oldest) {
				return;
			}
			await this.collection.deleteOne({ _id: oldest._id });
		}
	}

	async record(
		occurrence: ErrorOccurrence,
		bounds: ErrorStoreBounds
	): Promise<ErrorGroup | undefined> {
		const now = new Date();
		const expiresAt = expiryFrom(now, bounds.retentionDays);

		const existing = await this.collection.findOne({
			fingerprint: occurrence.fingerprint
		});

		if (existing) {
			const samples = admitSample(
				existing.samples,
				occurrence.record,
				bounds.samplesPerGroup
			);
			await this.collection.updateOne(
				{ _id: existing._id },
				{
					$inc: { occurrences: 1 },
					$set: {
						lastSeenAt: now,
						expiresAt,
						samples,
						/*
						 * The newest occurrence's message and origin win. Two occurrences sharing a
						 * fingerprint arose at the same place, so this only refreshes an interpolated
						 * detail — and the newest is the one an operator is about to act on.
						 */
						message: occurrence.message,
						origin: occurrence.origin
					}
				}
			);
			return {
				...existing,
				occurrences: existing.occurrences + 1,
				lastSeenAt: now,
				expiresAt,
				samples,
				message: occurrence.message,
				origin: occurrence.origin
			};
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
			await this.collection.insertOne(group);
			return group;
		} catch {
			/*
			 * Two instances recording the same new fault in the same instant: the unique fingerprint index
			 * refuses the second insert. Counting the occurrence against the winner is the correct
			 * outcome, and losing the race is not an error worth surfacing — the fault is recorded either
			 * way. Recursing once cannot loop, because the group now exists and the branch above takes it.
			 */
			return this.record(occurrence, bounds);
		}
	}

	async list(query: ErrorStoreQuery = {}): Promise<ErrorGroupPage> {
		const now = new Date();
		const filter = toFilter(query, now);
		const { limit, offset } = normalizeErrorPaging(query);

		/*
		 * `_id` descending after `lastSeenAt` descending makes the order total, so a page boundary cannot
		 * drop or repeat a group when two faults share a millisecond — which a storm makes ordinary.
		 * Served by the `{ lastSeenAt: 1, _id: 1 }` index traversed backwards: an index scan, not an
		 * in-memory sort.
		 */
		const [groups, total] = await Promise.all([
			this.collection
				.find(filter)
				.sort({ lastSeenAt: -1, _id: -1 })
				.skip(offset)
				.limit(limit)
				.toArray(),
			this.collection.countDocuments(filter)
		]);

		// Filled in by the route from the queue, which owns the counter; the store cannot know it.
		return { groups, total, dropped: 0 };
	}

	async get(id: string): Promise<ErrorGroup | undefined> {
		const found = await this.collection.findOne({
			_id: id,
			expiresAt: { $gt: new Date() }
		});
		return found ?? undefined;
	}

	async findByReference(
		reference: string
	): Promise<{ group: ErrorGroup; sample: ErrorRecord } | undefined> {
		const group = await this.collection.findOne({
			'samples.reference': reference,
			expiresAt: { $gt: new Date() }
		});
		if (!group) {
			return undefined;
		}
		const sample = group.samples.find(
			(candidate) => candidate.reference === reference
		);
		// The index matched the document, so the sample is present; the guard keeps the return type
		// honest rather than asserting it away.
		return sample ? { group, sample } : undefined;
	}

	async summarize(query: ErrorStoreQuery = {}): Promise<ErrorSummary> {
		const now = new Date();
		/*
		 * Projected without `samples`, which is the whole weight of a document, then summed through the
		 * shared helper. An aggregation pipeline would push the grouping into the server, but it would
		 * also be a second definition of "most frequent first, ties broken by key" — and the two adapters
		 * agreeing on that ordering matters more here than the round trip does at a four-figure group cap.
		 */
		const groups = (await this.collection
			.find(toFilter(query, now), { projection: { samples: 0 } })
			.toArray()) as ErrorGroup[];

		return {
			total: totalOccurrences(groups),
			byErrorCode: summarizeBy(groups, (group) => group.errorCode),
			byRoute: summarizeBy(groups, (group) => group.route),
			dropped: 0
		};
	}

	async previewPurge(query: ErrorStoreQuery): Promise<ErrorPurgeEstimate> {
		const now = new Date();
		const groups = (await this.collection
			.find(toFilter(query, now), { projection: { occurrences: 1 } })
			.toArray()) as ErrorGroup[];

		return {
			groups: groups.length,
			occurrences: totalOccurrences(groups)
		};
	}

	async purge(query: ErrorStoreQuery): Promise<number> {
		const result = await this.collection.deleteMany(
			toFilter(query, new Date())
		);
		return result.deletedCount;
	}
}
