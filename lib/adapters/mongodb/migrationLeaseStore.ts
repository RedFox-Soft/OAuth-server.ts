import crypto from 'crypto';
import { ObjectId } from 'mongodb';

import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { MigrationLease, MigrationLeaseStoreInstance } from '../types.js';

/*
 * The migration run lease, as one document in the shared serviceConfig area — beside the singleton
 * secrets and the SMTP settings, told apart by a derived ObjectId, exactly as those are.
 *
 * Not in `schemaMigrations`, where a document's `_id` IS a declared migration id and a lease would
 * have to wear a fake one that every read of that collection would then have to remember to skip.
 */
function stringTo24CharHex(value: string): string {
	return crypto
		.createHash('sha256')
		.update(value)
		.digest('hex')
		.substring(0, 24);
}

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		(error as { code: unknown }).code === 11000
	);
}

export class MigrationLeaseStore implements MigrationLeaseStoreInstance {
	private collectionName: string = STORE_AREAS.serviceConfig;
	private leaseId = new ObjectId(stringTo24CharHex('migrationLock'));

	private collection() {
		return db.collection<{
			_id: ObjectId;
			holder: string;
			leaseExpiresAt: Date;
		}>(this.collectionName);
	}

	async read(): Promise<MigrationLease | null> {
		const found = await this.collection().findOne({ _id: this.leaseId });
		if (!found) return null;
		return { holder: found.holder, expiresAt: found.leaseExpiresAt };
	}

	/*
	 * One upsert whose filter matches only a lease that is free to take: absent, already this holder's,
	 * or expired. When a live lease is held by somebody else the filter misses and the upsert attempts
	 * an insert on the fixed `_id`, which the primary key refuses — and that duplicate-key error IS the
	 * contention signal, atomically and without a second round trip. The same trick
	 * `SingletonSecretStore.create` uses, and for the same reason.
	 *
	 * `leaseExpiresAt` rather than `expiresAt`: the latter is the field the storage inventory's expiry
	 * indexes are built on, and a document in a `reaped: null` area carrying it would be a trap for
	 * whoever later declares that area reaped.
	 */
	async acquire(holder: string, expiresAt: Date): Promise<boolean> {
		try {
			const result = await this.collection().updateOne(
				{
					_id: this.leaseId,
					$or: [{ holder }, { leaseExpiresAt: { $lte: new Date() } }]
				},
				{ $set: { holder, leaseExpiresAt: expiresAt } },
				{ upsert: true }
			);
			return result.matchedCount > 0 || result.upsertedCount > 0;
		} catch (error) {
			if (isDuplicateKey(error)) return false;
			throw error;
		}
	}

	async release(holder: string): Promise<void> {
		await this.collection().deleteOne({ _id: this.leaseId, holder });
	}
}
