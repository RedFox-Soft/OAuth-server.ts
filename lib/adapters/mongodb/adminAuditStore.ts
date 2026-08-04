import type { Filter } from 'mongodb';
import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	AdminAuditEntry,
	AdminAuditPage,
	AdminAuditQuery,
	AdminAuditStoreInstance
} from '../types.js';
import {
	normalizeAuditPaging,
	withAuditDefaults
} from '../../helpers/admin_audit_query.js';
import nanoid from '../../helpers/nanoid.js';

/*
 * Translates a query into a filter document. Every clause is an exact match except the time window,
 * and the actor is a two-arm `$or` because one filter has to reach both actorId and actorEmail — both
 * are indexed for it (see the adminAudit entry in the storage inventory).
 */
function toFilter(query: AdminAuditQuery): Filter<AdminAuditEntry> {
	const filter: Filter<AdminAuditEntry> = {};
	if (query.actor !== undefined) {
		filter.$or = [{ actorId: query.actor }, { actorEmail: query.actor }];
	}
	if (query.action !== undefined) {
		filter.action = query.action;
	}
	if (query.targetType !== undefined) {
		filter.targetType = query.targetType;
	}
	if (query.targetId !== undefined) {
		filter.targetId = query.targetId;
	}
	if (query.targetScope !== undefined) {
		filter.targetScope = query.targetScope;
	}
	if (query.from !== undefined || query.to !== undefined) {
		// Inclusive both ends, matching the memory adapter. Order between the bounds is not policed
		// here — the route refuses a backwards window, where the caller can be told why.
		filter.timestamp = {
			...(query.from === undefined ? {} : { $gte: query.from }),
			...(query.to === undefined ? {} : { $lte: query.to })
		};
	}
	return filter;
}

// Append-only MongoDB admin audit log (collection `adminAudit`). Only inserts and reads —
// no update/delete — so the trail is immutable through this adapter.
export class AdminAuditStore implements AdminAuditStoreInstance {
	private collection = db.collection<AdminAuditEntry>(STORE_AREAS.adminAudit);

	async record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry> {
		const saved: AdminAuditEntry = {
			_id: nanoid(),
			timestamp: new Date(),
			...entry
		};
		await this.collection.insertOne(saved);
		return saved;
	}

	async list(query: AdminAuditQuery = {}): Promise<AdminAuditPage> {
		const filter = toFilter(query);
		const { limit, offset } = normalizeAuditPaging(query);

		/*
		 * `_id` descending after `timestamp` descending makes the order total, so a page boundary cannot
		 * drop or repeat an entry when two actions share a timestamp. Served by the
		 * `{ timestamp: 1, _id: 1 }` index traversed backwards — an index scan, not an in-memory sort,
		 * which is what keeps a page of a 100k-entry trail as cheap as a page of an empty one.
		 */
		const [documents, total] = await Promise.all([
			this.collection
				.find(filter)
				.sort({ timestamp: -1, _id: -1 })
				.skip(offset)
				.limit(limit)
				.toArray(),
			this.collection.countDocuments(filter)
		]);

		return {
			entries: documents.map((entry) => withAuditDefaults(entry)),
			total
		};
	}
}
