import { sql } from './db.js';
import { docOf } from './json.js';
import { type UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { JWKSStoreInstance } from '../types.js';

/*
 * The signing keys.
 *
 * The `kid` is the row's primary key, so there is no separate identity to keep in step — MongoDB
 * carries an `_id` beside the `kid` and has to strip it, plus an `updatedAt`, on the way out. Here
 * the document column holds the JWK and nothing else, which is why nothing needs discarding on read.
 *
 * The `kid` is also kept inside the document. That is a deliberate duplication: the declared unique
 * index is on `(doc->>'kid')`, so keeping the field means the constraint the inventory declares is
 * genuinely enforced rather than merely implied by the primary key.
 */
export class JWKSStore implements JWKSStoreInstance {
	private area: string = STORE_AREAS.jwks;

	async get(keyId: string): Promise<UnnormalizedJWK | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${keyId}
		`;
		return this.jwkOf(rows[0]) ?? null;
	}

	async set(keyId: string, key: UnnormalizedJWK): Promise<void> {
		const handle = sql();
		const doc = { ...key, kid: keyId };
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${keyId}, ${doc}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
		`;
	}

	async delete(keyId: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${keyId}`;
	}

	async getAll(): Promise<UnnormalizedJWK[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		const jwks: (UnnormalizedJWK | undefined)[] = rows.map((row: unknown) =>
			this.jwkOf(row)
		);
		return jwks.filter((jwk): jwk is UnnormalizedJWK => jwk !== undefined);
	}

	/*
	 * Claims only that the stored document is a schema-shaped JWK — not that it is normalized. Nothing
	 * but a read can tell us what is in a jsonb column, and `verifyJWKs` is what checks even that, on
	 * the way in to the key set.
	 */
	private jwkOf(row: unknown): UnnormalizedJWK | undefined {
		return docOf<UnnormalizedJWK>(row);
	}
}
