import crypto from 'crypto';
import { Binary, ObjectId } from 'mongodb';
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

	/*
	 * Unwrapping the driver's wrapper is what makes the round trip survivable. A Buffer goes in, but
	 * BSON has no Buffer, so a `Binary` comes back — the exact shape configs/nonceSecret.ts rejects,
	 * since a Binary is not a Uint8Array and derives no nonces. Left wrapped, every boot read an
	 * unusable secret, replaced it, read the replacement back equally unusable, and refused to start.
	 *
	 * Translating out of the wrapper is the adapter's job, not the caller's guard: the wrapper is this
	 * driver's representation choice, and the guard stays a check on the material rather than a
	 * catalogue of storage encodings. So any subtype is unwrapped, not just the default one written
	 * here — `value()` yields bytes either way, and the caller's length check is what judges them —
	 * while a non-binary value passes through untouched, for the caller to repair rather than have
	 * coerced into merely looking usable.
	 */
	async read(): Promise<unknown> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ _id: this.secretId });
		const secret = result?.secret ?? null;
		return secret instanceof Binary ? secret.value() : secret;
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
	 *
	 * `observed` arrives as the bytes `read` unwrapped, not as the Binary the driver produced, and the
	 * filter still matches: a Uint8Array and a Buffer serialise to byte-identical BSON binary, so the
	 * unwrap costs the conditional write nothing.
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
