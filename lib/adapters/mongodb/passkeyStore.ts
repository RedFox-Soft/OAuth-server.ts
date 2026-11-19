import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { Passkey, type PasskeyStoreInstance } from '../types.js';

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

/*
 * People's passkeys (specs/139). One credential id per project is the unique `{bucketId, credentialId}` index the
 * inventory declares, so a duplicate add is refused by the datastore even under a concurrent write. Every
 * conditional write is one `updateOne` whose filter is the condition, so two racing writers cannot both match.
 */
export class PasskeyStore implements PasskeyStoreInstance {
	private collection = db.collection<Passkey>(STORE_AREAS.passkeys);

	async create(record: Passkey): Promise<'created' | 'exists'> {
		try {
			await this.collection.insertOne({ ...record });
			return 'created';
		} catch (error) {
			if (isDuplicateKey(error)) return 'exists';
			throw error;
		}
	}

	async findByCredential(
		bucketId: string,
		credentialId: string
	): Promise<Passkey | null> {
		return this.recordOf(
			await this.collection.findOne({ bucketId, credentialId })
		);
	}

	async find(bucketId: string, id: string): Promise<Passkey | null> {
		return this.recordOf(await this.collection.findOne({ _id: id, bucketId }));
	}

	async listOf(bucketId: string, accountId: string): Promise<Passkey[]> {
		const found = await this.collection.find({ bucketId, accountId }).toArray();
		return found.map((record) =>
			documentOf(STORE_AREAS.passkeys, Passkey, record)
		);
	}

	async countOf(bucketId: string, accountId: string): Promise<number> {
		return this.collection.countDocuments({ bucketId, accountId });
	}

	async recordUse(
		bucketId: string,
		id: string,
		use: { counter: number; backedUp: boolean; at: Date }
	): Promise<boolean> {
		const result = await this.collection.updateOne(
			{
				_id: id,
				bucketId,
				copiedAt: { $exists: false },
				/* A counter that stays at zero is a device that never counts; any other must move forward. */
				counter: use.counter === 0 ? 0 : { $lt: use.counter }
			},
			{
				$set: {
					counter: use.counter,
					backedUp: use.backedUp,
					lastUsedAt: use.at
				}
			}
		);
		return result.modifiedCount === 1;
	}

	async markCopied(bucketId: string, id: string, at: Date): Promise<void> {
		await this.collection.updateOne(
			{ _id: id, bucketId, copiedAt: { $exists: false } },
			{ $set: { copiedAt: at } }
		);
	}

	async rename(
		bucketId: string,
		accountId: string,
		id: string,
		name: string | undefined
	): Promise<boolean> {
		const result = await this.collection.updateOne(
			{ _id: id, bucketId, accountId },
			name === undefined ? { $unset: { name: '' } } : { $set: { name } }
		);
		return result.matchedCount === 1;
	}

	async remove(
		bucketId: string,
		accountId: string,
		id: string
	): Promise<boolean> {
		const result = await this.collection.deleteOne({
			_id: id,
			bucketId,
			accountId
		});
		return result.deletedCount === 1;
	}

	async removeAddedSince(
		bucketId: string,
		accountId: string,
		since: Date
	): Promise<number> {
		const result = await this.collection.deleteMany({
			bucketId,
			accountId,
			createdAt: { $gte: since }
		});
		return result.deletedCount;
	}

	async removeAllOf(bucketId: string, accountId: string): Promise<number> {
		return (await this.collection.deleteMany({ bucketId, accountId }))
			.deletedCount;
	}

	async removeAllIn(bucketId: string): Promise<number> {
		return (await this.collection.deleteMany({ bucketId })).deletedCount;
	}

	async spendNotMe(
		bucketId: string,
		id: string,
		digest: string,
		now: number
	): Promise<boolean> {
		const result = await this.collection.updateOne(
			{ _id: id, bucketId, 'notMe.digest': digest, 'notMe.exp': { $gt: now } },
			{ $unset: { notMe: '' } }
		);
		return result.modifiedCount === 1;
	}

	/* A `$group`, not `distinct`: `distinct` is outside Stable API version 1, which this server's client runs under strictly. */
	async holdersIn(bucketId: string): Promise<string[]> {
		const groups = await this.collection
			.aggregate<{ _id: unknown }>([
				{ $match: { bucketId } },
				{ $group: { _id: '$accountId' } }
			])
			.toArray();
		return groups
			.map((group) => group._id)
			.filter(
				(accountId): accountId is string => typeof accountId === 'string'
			);
	}

	private recordOf(found: unknown): Passkey | null {
		return found ? documentOf(STORE_AREAS.passkeys, Passkey, found) : null;
	}
}
