import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	OutsideAuthorizationServer,
	type OutsideAuthorizationServerStoreInstance
} from '../types.js';

function recordOf(found: unknown): OutsideAuthorizationServer | null {
	return found
		? documentOf(
				STORE_AREAS.outsideAuthorizationServers,
				OutsideAuthorizationServer,
				found
			)
		: null;
}

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

/*
 * Outside authorization server connections. `insertOne` enforces one issuer per project, not a read-then-write
 * check: the derived key is the `_id`, so a duplicate is a primary-key violation refused even under a
 * concurrent write.
 */
export class OutsideAuthorizationServerStore implements OutsideAuthorizationServerStoreInstance {
	private collection = db.collection<OutsideAuthorizationServer>(
		STORE_AREAS.outsideAuthorizationServers
	);

	async create(
		record: OutsideAuthorizationServer
	): Promise<OutsideAuthorizationServer> {
		try {
			await this.collection.insertOne({ ...record }, ABSENT_UNDEFINED);
		} catch (error) {
			if (isDuplicateKey(error)) {
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
		return recordOf(await this.collection.findOne({ _id: id }));
	}

	async listByBucket(bucketId: string): Promise<OutsideAuthorizationServer[]> {
		const found = await this.collection.find({ bucketId }).toArray();
		return found.map((record) =>
			documentOf(
				STORE_AREAS.outsideAuthorizationServers,
				OutsideAuthorizationServer,
				record
			)
		);
	}

	async replace(record: OutsideAuthorizationServer): Promise<void> {
		await this.collection.replaceOne(
			{ _id: record._id },
			record,
			ABSENT_UNDEFINED
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		const result = await this.collection.deleteMany({ bucketId });
		return result.deletedCount;
	}
}
