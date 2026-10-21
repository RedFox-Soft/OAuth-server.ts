import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	OutsideAuthorizationServer,
	type OutsideAuthorizationServerStoreInstance
} from '../types.js';

/*
 * Outside authorization server connections. A plain INSERT enforces one issuer per project: the derived key
 * is the primary key, so a duplicate is a constraint violation refused even under a concurrent write — the
 * same reasoning, and the same absence of `ON CONFLICT`, as the MongoDB store's bare `insertOne`.
 */
export class OutsideAuthorizationServerStore implements OutsideAuthorizationServerStoreInstance {
	private area: string = STORE_AREAS.outsideAuthorizationServers;

	async create(
		record: OutsideAuthorizationServer
	): Promise<OutsideAuthorizationServer> {
		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${record._id}, ${record}, NULL)
			`;
		} catch (error) {
			if (isUniqueViolation(error)) {
				throw new UniqueValueTaken(
					'outside authorization server',
					record.issuer
				);
			}
			throw error;
		}
		return record;
	}

	async find(id: string): Promise<OutsideAuthorizationServer | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.recordOf(rows[0]);
	}

	async listByBucket(bucketId: string): Promise<OutsideAuthorizationServer[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
		`;
		return rows
			.map((row: unknown) => this.recordOf(row))
			.filter(
				(
					record: OutsideAuthorizationServer | null
				): record is OutsideAuthorizationServer => record !== null
			);
	}

	async replace(record: OutsideAuthorizationServer): Promise<void> {
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)} SET doc = ${record} WHERE id = ${record._id}
		`;
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.length;
	}

	private recordOf(row: unknown): OutsideAuthorizationServer | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, OutsideAuthorizationServer, doc);
	}
}
