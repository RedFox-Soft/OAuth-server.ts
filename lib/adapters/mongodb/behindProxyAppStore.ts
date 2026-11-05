import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { entriesOf } from '../../helpers/_/object.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	BehindProxyApp,
	type BehindProxyAppPatch,
	type BehindProxyAppStoreInstance,
	type BehindProxyAppUsage
} from '../types.js';

const FIRST_TIMES = [
	'firstAskedAt',
	'firstSignInAt',
	'firstAllowedAt'
] as const;

function recordOf(found: unknown): BehindProxyApp | null {
	return found
		? documentOf(STORE_AREAS.behindProxyApps, BehindProxyApp, found)
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
 * Apps behind a proxy. One address per bucket is the unique `{bucketId, address}` index's, so a duplicate is
 * refused even under a concurrent write — by `insertOne` on create and by the update itself on a change of
 * address, never by a read before either.
 */
export class BehindProxyAppStore implements BehindProxyAppStoreInstance {
	private collection = db.collection<BehindProxyApp>(
		STORE_AREAS.behindProxyApps
	);

	async listByBucket(bucketId: string): Promise<BehindProxyApp[]> {
		const found = await this.collection.find({ bucketId }).toArray();
		return found.map((record) =>
			documentOf(STORE_AREAS.behindProxyApps, BehindProxyApp, record)
		);
	}

	async find(id: string): Promise<BehindProxyApp | null> {
		return recordOf(await this.collection.findOne({ _id: id }));
	}

	async create(record: BehindProxyApp): Promise<BehindProxyApp> {
		try {
			await this.collection.insertOne({ ...record }, ABSENT_UNDEFINED);
		} catch (error) {
			if (isDuplicateKey(error)) {
				throw new UniqueValueTaken('address', record.address);
			}
			throw error;
		}
		return record;
	}

	async update(
		id: string,
		patch: BehindProxyAppPatch
	): Promise<BehindProxyApp | null> {
		const set: Record<string, unknown> = { updatedAt: new Date() };
		for (const [field, value] of entriesOf(patch)) {
			if (value !== undefined) set[field] = value;
		}
		try {
			return recordOf(
				await this.collection.findOneAndUpdate(
					{ _id: id },
					{ $set: set },
					{ returnDocument: 'after' }
				)
			);
		} catch (error) {
			if (isDuplicateKey(error) && typeof patch.address === 'string') {
				throw new UniqueValueTaken('address', patch.address);
			}
			throw error;
		}
	}

	async delete(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const found = await this.collection
			.find({ bucketId }, { projection: { _id: 1 } })
			.toArray();
		const ids = found.map((record) => record._id);
		if (ids.length > 0) {
			await this.collection.deleteMany({ _id: { $in: ids } });
		}
		return ids;
	}

	/*
	 * One pipeline update, so each first time is kept where one is recorded (`$ifNull`) and written where none is,
	 * in the same write that moves `lastAskedAt`.
	 */
	async noteUsage(id: string, fields: BehindProxyAppUsage): Promise<void> {
		const set: Record<string, unknown> = {};
		for (const field of FIRST_TIMES) {
			const at = fields[field];
			if (at) set[field] = { $ifNull: [`$${field}`, at] };
		}
		if (fields.lastAskedAt) set.lastAskedAt = fields.lastAskedAt;
		if (Object.keys(set).length === 0) return;
		await this.collection.updateOne({ _id: id }, [{ $set: set }]);
	}
}
