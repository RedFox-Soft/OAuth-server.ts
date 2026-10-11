import type { Filter } from 'mongodb';
import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	AdminAuditEntry,
	type AdminAuditPage,
	type AdminAuditQuery,
	type AdminAuditStoreInstance
} from '../types.js';
import {
	normalizeAuditPaging,
	withAuditDefaults
} from '../../helpers/admin_audit_query.js';
import nanoid from '../../helpers/nanoid.js';
import { CONNECTION_ACTOR_PREFIX } from '../../consts/admin_audit_routes.js';

/* A user's text, matched literally: every character a regular expression gives meaning to is escaped. */
function literalPrefix(text: string): RegExp {
	return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`);
}

/*
 * Translates a query into a filter document. Every clause is an exact match except the time window and the
 * action prefix, and several are disjunctions: the actor reaches both actorId and actorEmail, the group
 * boundary both owner fields, a bucket four fields and a connection two — each arm indexed (see the
 * adminAudit entry in the storage inventory). A filter document holds one `$or`, so every disjunction goes
 * under `$and` as one clause of its own.
 */
function toFilter(query: AdminAuditQuery): Filter<AdminAuditEntry> {
	const filter: Filter<AdminAuditEntry> = {};
	const disjunctions: Filter<AdminAuditEntry>[][] = [];
	if (query.actor !== undefined) {
		disjunctions.push([{ actorId: query.actor }, { actorEmail: query.actor }]);
	}
	if (query.action !== undefined) {
		filter.action = query.action;
	}
	/*
	 * Anchored, so the index on `action` serves it as a range scan. Combined with an exact `action` under
	 * `$and` rather than overwriting it: both filters narrow, neither replaces the other.
	 */
	if (query.actionPrefix !== undefined) {
		const prefix = { action: { $regex: literalPrefix(query.actionPrefix) } };
		if (filter.action === undefined) {
			filter.action = prefix.action;
		} else {
			disjunctions.push([prefix]);
		}
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
	if (query.bucket !== undefined) {
		disjunctions.push([
			{ targetType: 'UserBucket', targetId: query.bucket },
			{ targetScope: query.bucket },
			{ bucketId: query.bucket },
			{ formerBucketId: query.bucket }
		]);
	}
	if (query.connection !== undefined) {
		disjunctions.push([
			{ actorId: `${CONNECTION_ACTOR_PREFIX}${query.connection}` },
			{ targetType: 'ProvisioningConnection', targetId: query.connection }
		]);
	}
	/*
	 * Applied here, where the entries are selected, rather than by filtering a wider result afterwards.
	 * This is the tenant boundary of the audit read: a restriction imposed after the fact is one a bug
	 * can skip while still answering 200.
	 *
	 * `$in` over an empty array matches nothing, which is the intended reading — see the note in
	 * matchesAuditQuery, which both adapters have to agree with.
	 *
	 * Two arms because a move belongs to the group it left as well as the one it joined.
	 */
	if (query.ownerGroupIds !== undefined) {
		disjunctions.push([
			{ ownerGroupId: { $in: query.ownerGroupIds } },
			{ formerOwnerGroupId: { $in: query.ownerGroupIds } }
		]);
	}
	if (disjunctions.length > 0) {
		filter.$and = disjunctions.map((arms) =>
			arms.length === 1 ? arms[0] : { $or: arms }
		);
	}
	if (query.viaSurface !== undefined) {
		/*
		 * A console entry stores no surface at all, so 'console' is the *absence* of the field, not a
		 * value to match. MongoDB's `null` equality matches both a missing field and an explicit null,
		 * which is exactly the memory adapter's `entry.viaSurface ?? 'console'`. Written out here because
		 * this is the seam where the two implementations would otherwise disagree, and the audit trail is
		 * the one surface whose whole purpose is to be trusted about what happened.
		 */
		filter.viaSurface =
			query.viaSurface === 'console'
				? null
				: query.viaSurface === 'mcp' ||
					  query.viaSurface === 'scim' ||
					  query.viaSurface === 'upstream'
					? query.viaSurface
					: { $in: [] };
	}
	if (query.viaClientId !== undefined) {
		filter.viaClientId = query.viaClientId;
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
		await this.collection.insertOne(saved, ABSENT_UNDEFINED);
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
			entries: documents.map((entry) =>
				withAuditDefaults(
					documentOf(STORE_AREAS.adminAudit, AdminAuditEntry, entry)
				)
			),
			total
		};
	}
}
