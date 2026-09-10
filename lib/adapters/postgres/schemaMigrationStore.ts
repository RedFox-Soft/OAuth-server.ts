import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	SchemaMigrationRecord,
	SchemaMigrationStoreInstance
} from '../types.js';

/*
 * The record of which schema migrations this database has had.
 *
 * The declared migration id IS the row's primary key, so "applied twice" is not a state this table
 * can hold, and no secondary index is needed: the runner reads the whole set once per run and compares
 * it against a declaration of the same small size.
 *
 * Unlike the MongoDB store beside it, a write here can join the transaction that carries the
 * migration's effect — PostgreSQL has transactional DDL and cross-table atomicity, and a standalone
 * `mongod` has neither. That is the one declared divergence in the migration layer, and it is why
 * every migration step must be safe to apply twice regardless of which backend runs it.
 */
export class SchemaMigrationStore implements SchemaMigrationStoreInstance {
	private area: string = STORE_AREAS.schemaMigrations;

	async all(): Promise<SchemaMigrationRecord[]> {
		const handle = sql();
		const rows = await handle`
			SELECT id, doc FROM ${handle(this.area)}
		`;
		return rows.map((row: unknown) => {
			const doc = docOf<{ appliedAt: string; checksum: string }>(row);
			return {
				id: (row as { id: string }).id,
				/* Stored inside the document, so it comes back as a string a jsonb round trip flattened —
				 * revived here rather than by the shared helper, because there is exactly one field. */
				appliedAt: new Date(doc?.appliedAt ?? 0),
				checksum: doc?.checksum ?? ''
			};
		});
	}

	/*
	 * `DO NOTHING` on conflict rather than an error. A duplicate means the migration was already
	 * recorded, which is the ordinary outcome after a crash between a migration's effect and this
	 * write on the *other* backend; keeping the two stores' behaviour identical here means a runner
	 * needs no per-backend branch, and re-recording is harmless either way.
	 */
	async record(entry: SchemaMigrationRecord): Promise<void> {
		const handle = sql();
		const doc = {
			appliedAt: entry.appliedAt,
			checksum: entry.checksum
		};
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${entry.id}, ${doc}, NULL)
			ON CONFLICT (id) DO NOTHING
		`;
	}

	/* Test- and verification-only, for the reason the MongoDB store states: editing history is what
	 * the checksum exists to detect, so the store offers no way to do it. */
	async reset(): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)}`;
	}
}
