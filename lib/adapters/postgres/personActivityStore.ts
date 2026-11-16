import { sql, type Tx } from './db.js';
import { docOf } from './json.js';
import {
	MAX_TOOLS_PER_ROW,
	OVERFLOW_ACCOUNT,
	PERSON_ACTIVITY_CHUNK
} from '../../consts/person_activity.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	PersonActivityRow,
	type PersonActivityPage,
	type PersonActivityQuery,
	type PersonActivityStoreInstance,
	type PersonActivityWriteResult
} from '../types.js';

/* Rows removed per statement when a project is destroyed, so one delete never holds a lock on millions of rows. */
const DESTROY_BATCH = 10_000;

/*
 * A person's activity. Times are compared as text: every one is written as an ISO-8601 UTC string of the same length,
 * which sorts the way time does, and the declared index is over `doc->>'lastAt'`.
 */
export class PersonActivityStore implements PersonActivityStoreInstance {
	private area: string = STORE_AREAS.personActivity;

	/*
	 * One transaction per chunk, its rows in `_id` order: two processes writing overlapping rows then lock them in the
	 * same order and cannot deadlock (40P01). A chunk is all or nothing, and a failed one is counted, never retried,
	 * because a retried addition counts twice (specs/133 research R11). Each document is passed as an object, never
	 * `JSON.stringify(...)` (lib/adapters/postgres/json.ts).
	 */
	async write(
		rows: readonly PersonActivityRow[]
	): Promise<PersonActivityWriteResult> {
		const sorted = [...rows].sort((a, b) =>
			a._id < b._id ? -1 : a._id > b._id ? 1 : 0
		);
		const handle = sql();
		let written = 0;
		let failed = 0;
		for (let start = 0; start < sorted.length; start += PERSON_ACTIVITY_CHUNK) {
			const chunk = sorted.slice(start, start + PERSON_ACTIVITY_CHUNK);
			try {
				await handle.begin(async (tx: Tx) => {
					for (const row of chunk) await this.upsert(tx, row);
				});
				written += chunk.length;
			} catch {
				failed += chunk.length;
			}
		}
		return { written, failed };
	}

	private async upsert(tx: Tx, row: PersonActivityRow): Promise<void> {
		const replaced = {
			...(row.address === undefined
				? {}
				: { address: row.address, addressFrom: row.addressFrom }),
			...(row.facts === undefined ? {} : { facts: row.facts }),
			...(row.device === undefined ? {} : { device: row.device })
		};
		/*
		 * An API use row's tools (specs/134 research R3): the names kept, then the new ones not kept, in their order, cut
		 * at twenty — the same list the buffer and MongoDB keep. A new name's position is offset past any kept one.
		 */
		const tools =
			row.tools !== undefined && row.tools.length > 0
				? tx`|| jsonb_build_object('tools', (
					SELECT COALESCE(jsonb_agg(kept.tool ORDER BY kept.position), '[]'::jsonb)
					FROM (
						SELECT tool, min(position) AS position FROM (
							SELECT tool, position FROM jsonb_array_elements_text(
								COALESCE(activity.doc->'tools', '[]'::jsonb)
							) WITH ORDINALITY AS old(tool, position)
							UNION ALL
							SELECT tool, position + 1000 FROM jsonb_array_elements_text(
								EXCLUDED.doc->'tools'
							) WITH ORDINALITY AS new(tool, position)
						) AS every GROUP BY tool ORDER BY position LIMIT ${MAX_TOOLS_PER_ROW}
					) AS kept
				))`
				: tx``;
		await tx`
			INSERT INTO ${tx(this.area)} AS activity (id, doc, expires_at)
			VALUES (${row._id}, ${row}, ${row.expiresAt})
			ON CONFLICT (id) DO UPDATE
			SET doc = (activity.doc || ${replaced})
				|| jsonb_build_object(
					'count', COALESCE((activity.doc->>'count')::int, 0) + ${row.count}::int,
					'firstAt', LEAST(activity.doc->>'firstAt', EXCLUDED.doc->>'firstAt'),
					'lastAt', GREATEST(activity.doc->>'lastAt', EXCLUDED.doc->>'lastAt'),
					'expiresAt', GREATEST(activity.doc->>'expiresAt', EXCLUDED.doc->>'expiresAt')
				)
				${tools},
				expires_at = GREATEST(activity.expires_at, EXCLUDED.expires_at)
		`;
	}

	async listForPerson(
		bucketId: string,
		accountId: string,
		query: PersonActivityQuery
	): Promise<PersonActivityPage> {
		const handle = sql();
		let where = handle`doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId} AND expires_at > ${query.now}`;
		if (query.kind !== undefined) {
			where = handle`${where} AND doc->>'kind' = ${query.kind}`;
		}
		if (query.outcome !== undefined) {
			where = handle`${where} AND doc->>'outcome' = ${query.outcome}`;
		}
		if (query.before !== undefined) {
			const at = query.before.lastAt.toISOString();
			where = handle`${where} AND (doc->>'lastAt' < ${at} OR (doc->>'lastAt' = ${at} AND id < ${query.before.id}))`;
		}
		const found = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE ${where}
			ORDER BY doc->>'lastAt' DESC, id DESC
			LIMIT ${Math.max(query.limit, 1) + 1}
		`;
		const rows = found
			.slice(0, query.limit)
			.map((row: unknown) =>
				documentOf(this.area, PersonActivityRow, docOf(row))
			);
		const last = rows.at(-1);
		return {
			rows,
			next:
				found.length > query.limit && last
					? { lastAt: last.lastAt, id: last._id }
					: null
		};
	}

	async overflowDays(
		bucketId: string,
		days: readonly string[],
		now: Date
	): Promise<string[]> {
		if (days.length === 0) return [];
		const handle = sql();
		const found = await handle<{ day: string }[]>`
			SELECT DISTINCT doc->>'day' AS day FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'accountId' = ${OVERFLOW_ACCOUNT}
				AND doc->>'day' = ANY(${handle.array([...days], 'text')})
				AND expires_at > ${now}
		`;
		return found.map((row) => row.day);
	}

	/* On `{bucketId, outcome, lastAt}`: never the project's use rows (specs/134 research R6). */
	async listRefusals(
		bucketId: string,
		query: { since: Date; now: Date; limit: number }
	): Promise<PersonActivityRow[]> {
		const handle = sql();
		const found = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'outcome' IN ('refused', 'sign_in_again')
				AND doc->>'lastAt' >= ${query.since.toISOString()}
				AND expires_at > ${query.now}
				AND doc->>'accountId' <> ${OVERFLOW_ACCOUNT}
			ORDER BY doc->>'lastAt' DESC, id DESC
			LIMIT ${Math.max(query.limit, 1)}
		`;
		return found.map((row: unknown) =>
			documentOf(this.area, PersonActivityRow, docOf(row))
		);
	}

	async destroyPerson(bucketId: string, accountId: string): Promise<number> {
		const handle = sql();
		const removed = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
			RETURNING id
		`;
		return removed.length;
	}

	async destroyBucket(bucketId: string): Promise<number> {
		const handle = sql();
		let total = 0;
		for (;;) {
			const removed = await handle`
				DELETE FROM ${handle(this.area)}
				WHERE id IN (
					SELECT id FROM ${handle(this.area)}
					WHERE doc->>'bucketId' = ${bucketId}
					LIMIT ${DESTROY_BATCH}
				)
				RETURNING id
			`;
			total += removed.length;
			if (removed.length < DESTROY_BATCH) return total;
		}
	}
}
