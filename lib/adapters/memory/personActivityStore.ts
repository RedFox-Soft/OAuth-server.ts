import { OVERFLOW_ACCOUNT } from '../../consts/person_activity.js';
import type {
	PersonActivityPage,
	PersonActivityQuery,
	PersonActivityRow,
	PersonActivityStoreInstance,
	PersonActivityWriteResult
} from '../types.js';
import { addTo, isBefore, newestFirst } from '../person_activity_rows.js';

/*
 * In-memory activity. Every write is a synchronous read-and-set with no `await` between, so two flushes cannot
 * interleave inside one row and no count is lost.
 */
export class PersonActivityStore implements PersonActivityStoreInstance {
	private rows = new Map<string, PersonActivityRow>();

	async write(
		rows: readonly PersonActivityRow[]
	): Promise<PersonActivityWriteResult> {
		for (const row of rows) {
			const existing = this.rows.get(row._id);
			this.rows.set(
				row._id,
				existing ? addTo(existing, row) : structuredClone(row)
			);
		}
		return { written: rows.length, failed: 0 };
	}

	async listForPerson(
		bucketId: string,
		accountId: string,
		query: PersonActivityQuery
	): Promise<PersonActivityPage> {
		const matching = [...this.rows.values()]
			.filter(
				(row) =>
					row.bucketId === bucketId &&
					row.accountId === accountId &&
					row.expiresAt.getTime() > query.now.getTime() &&
					(query.kind === undefined || row.kind === query.kind) &&
					(query.outcome === undefined || row.outcome === query.outcome) &&
					(query.before === undefined || isBefore(row, query.before))
			)
			.sort(newestFirst);
		const page = matching.slice(0, query.limit);
		const last = page.at(-1);
		return {
			rows: page.map((row) => structuredClone(row)),
			next:
				matching.length > query.limit && last
					? { lastAt: last.lastAt, id: last._id }
					: null
		};
	}

	async overflowDays(
		bucketId: string,
		days: readonly string[],
		now: Date
	): Promise<string[]> {
		const found = new Set<string>();
		for (const row of this.rows.values()) {
			if (
				row.bucketId === bucketId &&
				row.accountId === OVERFLOW_ACCOUNT &&
				days.includes(row.day) &&
				row.expiresAt.getTime() > now.getTime()
			) {
				found.add(row.day);
			}
		}
		return [...found];
	}

	async destroyPerson(bucketId: string, accountId: string): Promise<number> {
		return this.destroyWhere(
			(row) => row.bucketId === bucketId && row.accountId === accountId
		);
	}

	async destroyBucket(bucketId: string): Promise<number> {
		return this.destroyWhere((row) => row.bucketId === bucketId);
	}

	private destroyWhere(match: (row: PersonActivityRow) => boolean): number {
		let destroyed = 0;
		for (const [id, row] of this.rows) {
			if (match(row)) {
				this.rows.delete(id);
				destroyed += 1;
			}
		}
		return destroyed;
	}
}
