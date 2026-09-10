import type { SQL } from 'bun';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
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

const DATE_FIELDS = ['timestamp'] as const;

/*
 * Timestamps are compared as text, and that is deliberate rather than lazy.
 *
 * The entry's `timestamp` lives inside the document, and the index the inventory declares is over
 * `(doc->>'timestamp')` — a text expression. `JSON.stringify` writes a Date as ISO-8601 in UTC with a
 * trailing `Z`, a format whose lexicographic order IS its chronological order, so a text comparison
 * gives the right answer and the index can serve it. Casting to timestamptz in the predicate would be
 * equally correct and would silently stop using the index, turning every filtered audit read into a
 * sequential scan of the whole trail.
 */
function isoBound(value: Date): string {
	return value.toISOString();
}

/*
 * Builds the WHERE clause. Every clause is an exact match except the time window, and the actor is a
 * two-arm OR because one filter has to reach both actorId and actorEmail — both are indexed for it.
 */
function conditionsFor(handle: SQL, query: AdminAuditQuery) {
	let where = handle`TRUE`;
	/* Typed from the value rather than named: a tagged-template call and the identifier helper share
	 * the `SQL` callable, so `ReturnType<SQL>` resolves to the wrong one of the two. */
	const and = (fragment: typeof where) => {
		where = handle`${where} AND ${fragment}`;
	};

	if (query.actor !== undefined) {
		and(
			handle`(doc->>'actorId' = ${query.actor} OR doc->>'actorEmail' = ${query.actor})`
		);
	}
	if (query.action !== undefined) {
		and(handle`doc->>'action' = ${query.action}`);
	}
	if (query.targetType !== undefined) {
		and(handle`doc->>'targetType' = ${query.targetType}`);
	}
	if (query.targetId !== undefined) {
		and(handle`doc->>'targetId' = ${query.targetId}`);
	}
	if (query.targetScope !== undefined) {
		and(handle`doc->>'targetScope' = ${query.targetScope}`);
	}

	/*
	 * The tenant boundary of the audit read, applied where the entries are selected rather than by
	 * filtering a wider result afterwards: a restriction imposed after the fact is one a bug can skip
	 * while still answering 200.
	 *
	 * `= ANY` over an empty array matches nothing, which is the intended reading and the same answer
	 * `$in: []` gives — both adapters have to agree with `matchesAuditQuery` here.
	 */
	if (query.ownerGroupIds !== undefined) {
		and(handle`doc->>'ownerGroupId' = ANY(${query.ownerGroupIds}::text[])`);
	}

	if (query.viaSurface !== undefined) {
		/*
		 * A console entry stores no surface at all, so 'console' is the *absence* of the field rather
		 * than a value to match — which is what the memory adapter's `entry.viaSurface ?? 'console'`
		 * says and what MongoDB's `null` equality happens to do. Both a missing key and an explicit JSON
		 * null have to count, and they are different things in jsonb: a missing key yields SQL NULL, an
		 * explicit null yields jsonb `null`. Spelling out both is the only way the three adapters agree,
		 * and the audit trail is the one surface whose whole purpose is to be trusted about what
		 * happened.
		 */
		and(
			query.viaSurface === 'console'
				? handle`(doc->'viaSurface' IS NULL OR doc->'viaSurface' = 'null'::jsonb)`
				: handle`doc->>'viaSurface' = ${query.viaSurface}`
		);
	}
	if (query.viaClientId !== undefined) {
		and(handle`doc->>'viaClientId' = ${query.viaClientId}`);
	}

	// Inclusive both ends, matching the other adapters. Order between the bounds is not policed here —
	// the route refuses a backwards window, where the caller can be told why.
	if (query.from !== undefined) {
		and(handle`doc->>'timestamp' >= ${isoBound(query.from)}`);
	}
	if (query.to !== undefined) {
		and(handle`doc->>'timestamp' <= ${isoBound(query.to)}`);
	}

	return where;
}

/*
 * Append-only. Only inserts and reads — no update, no delete — so the trail is immutable through this
 * adapter, exactly as it is through the MongoDB one.
 */
export class AdminAuditStore implements AdminAuditStoreInstance {
	private area: string = STORE_AREAS.adminAudit;

	async record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry> {
		const saved: AdminAuditEntry = {
			_id: nanoid(),
			timestamp: new Date(),
			...entry
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${saved._id}, ${saved}, NULL)
		`;

		return saved;
	}

	async list(query: AdminAuditQuery = {}): Promise<AdminAuditPage> {
		const handle = sql();
		const where = conditionsFor(handle, query);
		const { limit, offset } = normalizeAuditPaging(query);

		/*
		 * `id` descending after the timestamp makes the order total, so a page boundary cannot drop or
		 * repeat an entry when two actions share a timestamp. Served by the declared
		 * `{ timestamp, _id }` index traversed backwards — an index scan, not an in-memory sort, which
		 * is what keeps a page of a 100k-entry trail as cheap as a page of an empty one.
		 */
		const [rows, counted] = await Promise.all([
			handle`
				SELECT doc FROM ${handle(this.area)}
				WHERE ${where}
				ORDER BY doc->>'timestamp' DESC, id DESC
				LIMIT ${limit} OFFSET ${offset}
			`,
			handle`
				SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${where}
			`
		]);

		const docs: (AdminAuditEntry | undefined)[] = rows.map((row: unknown) =>
			docOf<AdminAuditEntry>(row)
		);
		const entries = docs
			.filter((doc): doc is AdminAuditEntry => doc !== undefined)
			.map((doc) => withAuditDefaults(reviveDates(doc, DATE_FIELDS)));

		return {
			entries,
			total: Number((counted[0] as { total?: number } | undefined)?.total ?? 0)
		};
	}
}
