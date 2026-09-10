import crypto from 'crypto';

import { sql } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { SecretStoreInstance } from '../types.js';

/*
 * A permanent server-wide secret, held as raw bytes.
 *
 * This class is where the defect that prompted the constitution's storage-fidelity amendment lives in
 * its MongoDB form: a `Buffer` went into BSON, a `Binary` came back, the callers' `instanceof
 * Uint8Array` guards rejected it, and the server could not boot at all. Three secrets now share this
 * shape — the DPoP nonce secret, the pairwise identifier salt and the error-origin key — and the
 * salt's failure mode is the worst of them: replacing it permanently breaks every relying party's
 * account linkage.
 *
 * So the obligation here is not "store bytes" but "hand back something a caller's `instanceof
 * Uint8Array` accepts". PostgreSQL's `bytea` is the right column and the driver's decoding of it is
 * exactly the thing no database-free test can prove — `database/verify_postgres.ts` checks this first,
 * before anything else.
 *
 * Three writers share the `serviceConfig` area (see the note on STORE_AREAS.serviceConfig), told apart
 * by a derived id. MongoDB derives an ObjectId from the document name; here the same derived hex is
 * the text primary key, which needs no driver type and reads plainly in psql.
 */
function derivedId(documentName: string): string {
	return crypto
		.createHash('sha256')
		.update(documentName)
		.digest('hex')
		.substring(0, 24);
}

/*
 * Normalises whatever the driver produced into bytes, or leaves it alone.
 *
 * Translating out of a driver's representation is the adapter's job, not the caller's: the caller's
 * guard stays a check on the material rather than becoming a catalogue of storage encodings. That is
 * the lesson the MongoDB implementation records, and the reason this exists even though `bytea` is
 * expected to arrive as a Uint8Array already — "expected to" is what was believed about BSON too.
 *
 * A value that is not byte-like passes through untouched, for the caller to repair or refuse rather
 * than have coerced into merely looking usable.
 */
function toBytes(value: unknown): unknown {
	if (value === null || value === undefined) return null;
	if (value instanceof Uint8Array) return value;
	if (value instanceof ArrayBuffer) return new Uint8Array(value);
	return value;
}

export class SingletonSecretStore implements SecretStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private secretId: string;

	constructor(documentName: string) {
		this.secretId = derivedId(documentName);
	}

	async read(): Promise<unknown> {
		const handle = sql();
		const rows = await handle`
			SELECT secret FROM ${handle(this.area)} WHERE id = ${this.secretId}
		`;
		const row = rows[0] as { secret?: unknown } | undefined;
		return row === undefined ? null : toBytes(row.secret);
	}

	/*
	 * An insert that yields on conflict, rather than an upsert. With a fixed id, "somebody else got
	 * here first" is the ordinary outcome of two instances resolving the same secret at once, and it is
	 * not an error — it is the signal to adopt what they wrote.
	 *
	 * Returning `read()` unconditionally is what makes the caller adopt whatever is actually stored:
	 * its own candidate on a win, the other instance's on a loss. It also verifies the round trip,
	 * because the value it gets back came from the datastore rather than from its own hand — which is
	 * the check that would have caught the BSON defect on the very first boot.
	 */
	async create(secret: Buffer): Promise<unknown> {
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, secret, expires_at)
			VALUES (${this.secretId}, '{}'::jsonb, ${secret}, NULL)
			ON CONFLICT (id) DO NOTHING
		`;
		return this.read();
	}

	/*
	 * Conditional on the value the caller observed, so two instances that both find an unusable secret
	 * cannot both install a replacement: the second one's WHERE misses and it adopts the first's value.
	 *
	 * `observed === null` must not conjure a record — a caller that raced a delete would otherwise
	 * install a value nobody agreed on.
	 */
	async replace(observed: unknown, secret: Buffer): Promise<unknown> {
		if (observed !== null && observed !== undefined) {
			const handle = sql();
			await handle`
				UPDATE ${handle(this.area)}
				SET secret = ${secret}
				WHERE id = ${this.secretId} AND secret = ${observed}
			`;
		}
		return this.read();
	}
}
