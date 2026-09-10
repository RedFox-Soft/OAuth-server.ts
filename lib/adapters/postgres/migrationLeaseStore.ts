import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { MigrationLease, MigrationLeaseStoreInstance } from '../types.js';

/*
 * The migration run lease, as one row in the shared serviceConfig area — beside the singleton secrets
 * and the SMTP settings, told apart by a derived id, the same arrangement those already use.
 *
 * Not in `schemaMigrations`, where a row's id IS a declared migration id and a lease would have to
 * wear a fake one that every read of that table would then have to remember to skip.
 */
function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

interface StoredLease {
	holder: string;
	expiresAt: string;
}

export class MigrationLeaseStore implements MigrationLeaseStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private leaseId = derivedId('migrationLock');

	async read(): Promise<MigrationLease | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.leaseId}
		`;
		const stored = docOf<StoredLease>(rows[0]);
		if (stored === undefined) return null;
		return { holder: stored.holder, expiresAt: new Date(stored.expiresAt) };
	}

	/*
	 * One statement, and that is the whole point. `ON CONFLICT ... DO UPDATE ... WHERE` applies the
	 * update only when the held lease has expired or is already this holder's, and `RETURNING` reports
	 * whether it did. A read-then-write would let two runs both conclude the lease was free, which is
	 * exactly the failure a lock exists to prevent.
	 *
	 * The expiry comparison is on the stored text, cast to a timestamp. The value is written by
	 * `JSON.stringify` as ISO-8601 in UTC, which parses unambiguously.
	 */
	async acquire(holder: string, expiresAt: Date): Promise<boolean> {
		const handle = sql();
		const lease: StoredLease = {
			holder,
			expiresAt: expiresAt.toISOString()
		};

		const rows = await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${this.leaseId}, ${lease}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
			WHERE ${handle(this.area)}.doc->>'holder' = ${holder}
			   OR (${handle(this.area)}.doc->>'expiresAt')::timestamptz <= now()
			RETURNING id
		`;

		return rows.length > 0;
	}

	async release(holder: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.area)}
			WHERE id = ${this.leaseId} AND doc->>'holder' = ${holder}
		`;
	}
}
