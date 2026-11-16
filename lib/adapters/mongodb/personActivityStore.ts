import type { AnyBulkWriteOperation, Filter } from 'mongodb';

import { db } from './db.js';
import {
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

/*
 * The indexes of the operations a `bulkWrite` refused, read from its error. An unordered batch applies every other
 * operation, so only these are known not to have happened.
 */
function refusedIndexes(error: unknown): {
	duplicate: number[];
	other: number;
} {
	const writeErrors: unknown =
		typeof error === 'object' && error !== null && 'writeErrors' in error
			? error.writeErrors
			: undefined;
	// A driver error without per-operation detail: nothing is known to have been applied.
	if (!Array.isArray(writeErrors)) return { duplicate: [], other: -1 };
	const duplicate: number[] = [];
	let other = 0;
	const entries: unknown[] = writeErrors;
	for (const entry of entries) {
		const index =
			typeof entry === 'object' && entry !== null && 'index' in entry
				? entry.index
				: undefined;
		const code =
			typeof entry === 'object' && entry !== null && 'code' in entry
				? entry.code
				: undefined;
		if (code === 11000 && typeof index === 'number') {
			duplicate.push(index);
		} else {
			other += 1;
		}
	}
	return { duplicate, other };
}

function upsertOf(
	row: PersonActivityRow
): AnyBulkWriteOperation<PersonActivityRow> {
	const replaced = {
		...(row.address === undefined
			? {}
			: { address: row.address, addressFrom: row.addressFrom }),
		...(row.facts === undefined ? {} : { facts: row.facts }),
		...(row.device === undefined ? {} : { device: row.device })
	};
	return {
		updateOne: {
			filter: { _id: row._id },
			update: {
				/*
				 * `firstAt`, `lastAt`, `expiresAt` and `count` are absent here: one field may not be named in two
				 * operators, and `$min`, `$max` and `$inc` already set them on an insert.
				 */
				$setOnInsert: {
					bucketId: row.bucketId,
					accountId: row.accountId,
					day: row.day,
					kind: row.kind,
					outcome: row.outcome,
					reason: row.reason,
					place: row.place,
					...(row.method === undefined ? {} : { method: row.method }),
					...(row.freshness === undefined ? {} : { freshness: row.freshness })
				},
				...(Object.keys(replaced).length > 0 ? { $set: replaced } : {}),
				$inc: { count: row.count },
				$min: { firstAt: row.firstAt },
				$max: { lastAt: row.lastAt, expiresAt: row.expiresAt }
			},
			upsert: true
		}
	};
}

export class PersonActivityStore implements PersonActivityStoreInstance {
	private collection = db.collection<PersonActivityRow>(
		STORE_AREAS.personActivity
	);

	/*
	 * One unordered `bulkWrite` per chunk. Two processes inserting the same new row race on `_id`: the loser's
	 * operation fails with 11000 and is retried once, when it is an update of the winner's row. Any other refused
	 * operation is counted as failed and not retried, because the rest of the batch was applied and a retried addition
	 * counts twice; an unordered batch can therefore apply in part, which storage_divergences.ts declares.
	 */
	async write(
		rows: readonly PersonActivityRow[]
	): Promise<PersonActivityWriteResult> {
		let written = 0;
		let failed = 0;
		for (let start = 0; start < rows.length; start += PERSON_ACTIVITY_CHUNK) {
			const chunk = rows.slice(start, start + PERSON_ACTIVITY_CHUNK);
			try {
				await this.collection.bulkWrite(chunk.map(upsertOf), {
					ordered: false
				});
				written += chunk.length;
			} catch (error) {
				const refused = refusedIndexes(error);
				if (refused.other < 0) {
					failed += chunk.length;
					continue;
				}
				failed += refused.other;
				written += chunk.length - refused.other - refused.duplicate.length;
				for (const index of refused.duplicate) {
					try {
						await this.collection.bulkWrite([upsertOf(chunk[index])], {
							ordered: false
						});
						written += 1;
					} catch {
						failed += 1;
					}
				}
			}
		}
		return { written, failed };
	}

	async listForPerson(
		bucketId: string,
		accountId: string,
		query: PersonActivityQuery
	): Promise<PersonActivityPage> {
		const filter: Filter<PersonActivityRow> = {
			bucketId,
			accountId,
			expiresAt: { $gt: query.now },
			...(query.kind === undefined ? {} : { kind: query.kind }),
			...(query.outcome === undefined ? {} : { outcome: query.outcome }),
			...(query.before === undefined
				? {}
				: {
						$or: [
							{ lastAt: { $lt: query.before.lastAt } },
							{ lastAt: query.before.lastAt, _id: { $lt: query.before.id } }
						]
					})
		};
		/* One more than asked for, to know whether a next page exists. Never `limit(0)`, which reads everything. */
		const found = await this.collection
			.find(filter)
			.sort({ lastAt: -1, _id: -1 })
			.limit(Math.max(query.limit, 1) + 1)
			.toArray();
		const rows = found
			.slice(0, query.limit)
			.map((document) =>
				documentOf(STORE_AREAS.personActivity, PersonActivityRow, document)
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
		const found = await this.collection
			.find(
				{
					bucketId,
					accountId: OVERFLOW_ACCOUNT,
					day: { $in: [...days] },
					expiresAt: { $gt: now }
				},
				{ projection: { day: 1 } }
			)
			.toArray();
		return [...new Set(found.map((row) => row.day))];
	}

	async destroyPerson(bucketId: string, accountId: string): Promise<number> {
		const result = await this.collection.deleteMany({ bucketId, accountId });
		return result.deletedCount;
	}

	async destroyBucket(bucketId: string): Promise<number> {
		const result = await this.collection.deleteMany({ bucketId });
		return result.deletedCount;
	}
}
