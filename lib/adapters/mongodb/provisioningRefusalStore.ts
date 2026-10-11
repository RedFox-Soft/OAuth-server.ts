import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { refusalId } from '../refusal_records.js';
import {
	ProvisioningRefusal,
	type ProvisioningRefusalInput,
	type ProvisioningRefusalPage,
	type ProvisioningRefusalStoreInstance
} from '../types.js';

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

export class ProvisioningRefusalStore implements ProvisioningRefusalStoreInstance {
	private collection = db.collection<ProvisioningRefusal>(
		STORE_AREAS.provisioningRefusals
	);

	/*
	 * One single-document update, atomic on the server: `$setOnInsert` writes the record the first time and
	 * `$inc` counts every attempt. Two concurrent first notes of one `_id` can both try to insert; the loser
	 * gets duplicate key 11000, and its retry is then an update of the winner's document — the same
	 * operation, so no attempt is lost. `$max` keeps `lastAt` the latest even when notes land out of order.
	 */
	async note(input: ProvisioningRefusalInput): Promise<void> {
		const id = refusalId(input.connectionId, input.epoch, input.userId);
		const write = () =>
			this.collection.updateOne(
				{ _id: id },
				{
					$setOnInsert: {
						connectionId: input.connectionId,
						bucketId: input.bucketId,
						epoch: input.epoch,
						userId: input.userId,
						firstAt: input.at
					},
					$set: { operation: input.operation },
					$max: { lastAt: input.at },
					$inc: { attempts: 1 }
				},
				{ upsert: true }
			);
		try {
			await write();
		} catch (error) {
			if (!isDuplicateKey(error)) throw error;
			await write();
		}
	}

	async list(
		connectionId: string,
		epoch: number,
		limit: number
	): Promise<ProvisioningRefusalPage> {
		const filter = { connectionId, epoch };
		/* Never `limit(0)`, which MongoDB reads as no limit at all: a count-only read asks for no rows. */
		const [found, total] = await Promise.all([
			limit > 0
				? this.collection
						.find(filter)
						.sort({ lastAt: -1 })
						.limit(limit)
						.toArray()
				: [],
			this.collection.countDocuments(filter)
		]);
		return {
			refusals: found.map((document) =>
				documentOf(
					STORE_AREAS.provisioningRefusals,
					ProvisioningRefusal,
					document
				)
			),
			total
		};
	}

	async destroyByConnection(connectionId: string): Promise<number> {
		const { deletedCount } = await this.collection.deleteMany({ connectionId });
		return deletedCount;
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		const { deletedCount } = await this.collection.deleteMany({ bucketId });
		return deletedCount;
	}
}
