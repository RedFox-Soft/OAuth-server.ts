import { entriesOf } from '../../helpers/_/object.js';
import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import { providerKeyOf } from '../connection_keys.js';
import {
	ProvisioningConnection,
	type DeprovisioningHold,
	type NewProvisioningConnection,
	type ProvisioningConnectionPatch,
	type ProvisioningConnectionStoreInstance
} from '../types.js';

function connectionOf(found: unknown): ProvisioningConnection | null {
	return found
		? documentOf(
				STORE_AREAS.provisioningConnections,
				ProvisioningConnection,
				found
			)
		: null;
}

/*
 * Which unique key a refused write collided on, from the index MongoDB names in the error. An E11000 on an
 * index this store does not know is a defect and is rethrown by the caller.
 */
function takenFrom(error: unknown): UniqueValueTaken | null {
	if (
		typeof error !== 'object' ||
		error === null ||
		!('code' in error) ||
		error.code !== 11000
	) {
		return null;
	}
	const pattern =
		'keyPattern' in error && typeof error.keyPattern === 'object'
			? Object.keys(error.keyPattern ?? {})
			: [];
	if (pattern.includes('providerKey')) {
		return new UniqueValueTaken('provider', 'providerKey');
	}
	if (pattern.includes('staticTokenDigest')) {
		return new UniqueValueTaken('staticToken', 'digest');
	}
	return null;
}

/*
 * Provisioning connections. The unique indexes on `providerKey` and `staticTokenDigest` are what enforce
 * uniqueness, not a read-then-write check, so two administrators binding one provider at the same moment
 * cannot both succeed.
 */
export class ProvisioningConnectionStore implements ProvisioningConnectionStoreInstance {
	private collection = db.collection<ProvisioningConnection>(
		STORE_AREAS.provisioningConnections
	);

	async create(
		data: NewProvisioningConnection
	): Promise<ProvisioningConnection> {
		const now = new Date();
		const connection: ProvisioningConnection = {
			...data,
			providerKey: providerKeyOf(data.bucketId, data.providerId),
			createdAt: now,
			updatedAt: now
		};
		try {
			await this.collection.insertOne(connection, ABSENT_UNDEFINED);
		} catch (error) {
			const taken = takenFrom(error);
			if (taken) throw taken;
			throw error;
		}
		return connection;
	}

	async find(id: string): Promise<ProvisioningConnection | null> {
		return connectionOf(await this.collection.findOne({ _id: id }));
	}

	async listByBucket(bucketId: string): Promise<ProvisioningConnection[]> {
		const found = await this.collection.find({ bucketId }).toArray();
		return found
			.map((c) => connectionOf(c))
			.filter((c): c is ProvisioningConnection => c !== null);
	}

	async findByProvider(
		bucketId: string,
		providerId: string
	): Promise<ProvisioningConnection | null> {
		return connectionOf(
			await this.collection.findOne({
				providerKey: providerKeyOf(bucketId, providerId)
			})
		);
	}

	async findByStaticTokenDigest(
		digest: string
	): Promise<ProvisioningConnection | null> {
		return connectionOf(
			await this.collection.findOne({ staticTokenDigest: digest })
		);
	}

	/*
	 * A key present with an undefined value means "remove this field", which `$set` cannot say — the
	 * driver drops undefined values — so the patch is split the way the user store splits it. Revoking a
	 * static token is exactly such a removal, and a `$set` that silently kept the digest would keep the
	 * revoked token working.
	 */
	async update(
		id: string,
		patch: ProvisioningConnectionPatch
	): Promise<ProvisioningConnection | null> {
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const unset: Record<string, ''> = {};
		for (const [field, value] of entriesOf(patch)) {
			if (value === undefined) unset[field] = '';
			else set[field] = value;
		}
		try {
			const updated = await this.collection.findOneAndUpdate(
				{ _id: id },
				Object.keys(unset).length
					? { $set: set, $unset: unset }
					: { $set: set },
				{ returnDocument: 'after' }
			);
			return connectionOf(updated);
		} catch (error) {
			const taken = takenFrom(error);
			if (taken) throw taken;
			throw error;
		}
	}

	async touch(id: string, at: Date): Promise<void> {
		await this.collection.updateOne({ _id: id }, { $set: { lastUsedAt: at } });
	}

	/* Tested by type, so an absent field and a BSON null (the driver writes undefined as null) are both free. */
	async holdIfFree(id: string, hold: DeprovisioningHold): Promise<boolean> {
		const result = await this.collection.updateOne(
			{ _id: id, hold: { $not: { $type: 'object' } } },
			{ $set: { hold, updatedAt: new Date() } }
		);
		return result.modifiedCount === 1;
	}

	async releaseHold(id: string): Promise<ProvisioningConnection | null> {
		const released = await this.collection.findOneAndUpdate(
			{ _id: id, hold: { $type: 'object' } },
			{
				$unset: { hold: '' },
				$inc: { tallyEpoch: 1 },
				$set: { updatedAt: new Date() }
			},
			{ returnDocument: 'after' }
		);
		return connectionOf(released);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const ids = (
			await this.collection
				.find({ bucketId }, { projection: { _id: 1 } })
				.toArray()
		).map((c) => c._id);
		if (ids.length) await this.collection.deleteMany({ _id: { $in: ids } });
		return ids;
	}
}
