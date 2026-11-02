import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { ConnectedAccount } from '../../connected_services/types.js';
import type { ConnectedAccountStoreInstance } from '../types.js';

/*
 * Connected accounts (specs/117). `ON CONFLICT (id)` on the derived id replaces the document whole, as the
 * MongoDB store's upserting `replaceOne` does; `xmax = 0` on the returned row is PostgreSQL's own answer to
 * whether the row was inserted rather than updated.
 */
export class ConnectedAccountStore implements ConnectedAccountStoreInstance {
	private area: string = STORE_AREAS.connectedAccounts;

	async put(record: ConnectedAccount): Promise<{ created: boolean }> {
		const handle = sql();
		const rows = await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${record._id}, ${record}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
			RETURNING (xmax = 0) AS inserted
		`;
		const first: unknown = rows[0];
		return {
			created:
				typeof first === 'object' &&
				first !== null &&
				'inserted' in first &&
				first.inserted === true
		};
	}

	async find(bucketId: string, id: string): Promise<ConnectedAccount | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
		`;
		return this.recordOf(rows[0]);
	}

	async listByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
		`;
		return this.recordsOf(rows);
	}

	async countByAccountAndService(
		bucketId: string,
		accountId: string,
		serviceId: string
	): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS n FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'accountId' = ${accountId}
				AND doc->>'serviceId' = ${serviceId}
		`;
		return countOf(rows[0]);
	}

	async countByService(bucketId: string, serviceId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS n FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'serviceId' = ${serviceId}
		`;
		return countOf(rows[0]);
	}

	async destroy(
		bucketId: string,
		id: string
	): Promise<ConnectedAccount | null> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
			RETURNING doc
		`;
		return this.recordOf(rows[0]);
	}

	async destroyByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	async destroyByService(
		bucketId: string,
		serviceId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'serviceId' = ${serviceId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	async destroyByBucket(bucketId: string): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	private recordOf(row: unknown): ConnectedAccount | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, ConnectedAccount, doc);
	}

	private recordsOf(rows: readonly unknown[]): ConnectedAccount[] {
		return rows
			.map((row) => this.recordOf(row))
			.filter((record): record is ConnectedAccount => record !== null);
	}
}

function countOf(row: unknown): number {
	return typeof row === 'object' && row !== null && 'n' in row
		? Number(row.n)
		: 0;
}
