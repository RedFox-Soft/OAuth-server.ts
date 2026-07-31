import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { DPoPNonceSecretStoreInstance } from '../types.js';

function stringTo24CharHex(str: string) {
	const hash = crypto.createHash('sha256').update(str).digest('hex');
	return hash.substring(0, 24);
}

/* A duplicate key on the fixed _id is not an error here — it is how a losing writer learns it lost. */
function isDuplicateKey(err: unknown): boolean {
	return (
		typeof err === 'object' &&
		err !== null &&
		'code' in err &&
		(err as { code: unknown }).code === 11000
	);
}

export class DPoPNonceSecretStore implements DPoPNonceSecretStoreInstance {
	/* Third writer of the area — see the note on STORE_AREAS.serviceConfig. The three singleton
	 * documents are told apart only by their derived ObjectIds, which is why the inventory carries
	 * one entry for all of them. */
	private collectionName: string = STORE_AREAS.serviceConfig;
	private secretId = new ObjectId(stringTo24CharHex('dpopNonceSecret'));

	async read(): Promise<unknown> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ _id: this.secretId });
		return result?.secret ?? null;
	}

	/*
	 * An insert rather than an upsert: with a fixed _id, a duplicate-key result IS the conflict
	 * signal, atomically and without a second round trip. Returning `read()` unconditionally is what
	 * makes the caller adopt whatever is actually stored — its own candidate on a win, the other
	 * instance's on a loss — and simultaneously verifies the round trip, since the value it gets back
	 * came from the datastore rather than from its own hand.
	 */
	async create(secret: Buffer): Promise<unknown> {
		try {
			await db
				.collection(this.collectionName)
				.insertOne({ _id: this.secretId, secret, updatedAt: new Date() });
		} catch (err) {
			if (!isDuplicateKey(err)) {
				throw err;
			}
		}
		return this.read();
	}

	/*
	 * Conditional on the value the caller observed, so two instances that both find an unusable
	 * secret cannot both install their own replacement: the second one's filter misses and it adopts
	 * the first one's value. Matching a binary value in a filter is exactly what is wanted — if the
	 * stored shape is something other than what was observed, the write must not take effect.
	 */
	async replace(observed: unknown, secret: Buffer): Promise<unknown> {
		if (observed !== null) {
			await db
				.collection(this.collectionName)
				.updateOne(
					{ _id: this.secretId, secret: observed },
					{ $set: { secret, updatedAt: new Date() } }
				);
		}
		return this.read();
	}
}
