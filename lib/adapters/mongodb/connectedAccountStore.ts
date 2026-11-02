import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { ConnectedAccount } from '../../connected_services/types.js';
import type { ConnectedAccountStoreInstance } from '../types.js';

/*
 * Connected accounts (specs/117). `replaceOne` with `upsert` on the derived `_id`: a reconnect of the same
 * upstream account replaces the record whole, so a token the provider stopped issuing (no refresh token this
 * time) does not survive from the previous connection.
 */
export class ConnectedAccountStore implements ConnectedAccountStoreInstance {
	private collection = db.collection<ConnectedAccount>(
		STORE_AREAS.connectedAccounts
	);

	async put(record: ConnectedAccount): Promise<{ created: boolean }> {
		const result = await this.collection.replaceOne(
			{ _id: record._id },
			{ ...record },
			{ ...ABSENT_UNDEFINED, upsert: true }
		);
		return { created: result.upsertedCount === 1 };
	}

	async find(bucketId: string, id: string): Promise<ConnectedAccount | null> {
		return this.recordOf(await this.collection.findOne({ _id: id, bucketId }));
	}

	async listByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		return this.recordsOf(
			await this.collection.find({ bucketId, accountId }).toArray()
		);
	}

	async countByAccountAndService(
		bucketId: string,
		accountId: string,
		serviceId: string
	): Promise<number> {
		return this.collection.countDocuments({ bucketId, accountId, serviceId });
	}

	async countByService(bucketId: string, serviceId: string): Promise<number> {
		return this.collection.countDocuments({ bucketId, serviceId });
	}

	async destroy(
		bucketId: string,
		id: string
	): Promise<ConnectedAccount | null> {
		return this.recordOf(
			await this.collection.findOneAndDelete({ _id: id, bucketId })
		);
	}

	async destroyByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		return this.removeAll({ bucketId, accountId });
	}

	async destroyByService(
		bucketId: string,
		serviceId: string
	): Promise<ConnectedAccount[]> {
		return this.removeAll({ bucketId, serviceId });
	}

	async destroyByBucket(bucketId: string): Promise<ConnectedAccount[]> {
		return this.removeAll({ bucketId });
	}

	/*
	 * Read, then delete exactly the ids read: a record written between the two is not removed by this call, and
	 * its own deletion path (the next cascade, or the person) finds it, rather than it going without a revocation.
	 */
	private async removeAll(
		filter: Partial<Record<'bucketId' | 'accountId' | 'serviceId', string>>
	): Promise<ConnectedAccount[]> {
		const found = this.recordsOf(await this.collection.find(filter).toArray());
		if (found.length > 0) {
			await this.collection.deleteMany({
				_id: { $in: found.map((record) => record._id) }
			});
		}
		return found;
	}

	private recordOf(found: unknown): ConnectedAccount | null {
		return found
			? documentOf(STORE_AREAS.connectedAccounts, ConnectedAccount, found)
			: null;
	}

	private recordsOf(found: unknown[]): ConnectedAccount[] {
		return found.map((record) =>
			documentOf(STORE_AREAS.connectedAccounts, ConnectedAccount, record)
		);
	}
}
