import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	SchemaMigrationRecord,
	SchemaMigrationStoreInstance
} from '../types.js';

/*
 * The record of which schema migrations this database has had.
 *
 * The declared migration id IS the document `_id`, so "applied twice" is not a state this collection
 * can hold, and no secondary index is needed: the runner reads the whole set once per run and compares
 * it against a declaration of the same small size.
 *
 * Note what this store deliberately cannot do. There is no update and no way to change an id or a
 * checksum, for the reason the audit store exposes neither: editing a released migration's record is
 * precisely what the checksum exists to detect, so offering the operation would defeat the detection.
 * `reset` is the one exception, and it exists for the throwaway-database verification alone.
 */
export class SchemaMigrationStore implements SchemaMigrationStoreInstance {
	private collectionName: string = STORE_AREAS.schemaMigrations;

	private collection() {
		return db.collection<{
			_id: string;
			appliedAt: Date;
			checksum: string;
		}>(this.collectionName);
	}

	async all(): Promise<SchemaMigrationRecord[]> {
		const docs = await this.collection().find({}).toArray();
		return docs.map((doc) => ({
			id: doc._id,
			appliedAt: doc.appliedAt,
			checksum: doc.checksum
		}));
	}

	/*
	 * An insert, not an upsert. A duplicate key here means the migration was already recorded, which is
	 * the ordinary outcome of the one window this backend cannot close: a standalone `mongod` has no
	 * multi-document transaction, so a crash between a migration's effect and this write leaves the
	 * effect applied and unrecorded, and the next run applies it again. Swallowing the duplicate is what
	 * lets that re-run finish rather than dying on its own bookkeeping.
	 */
	async record(entry: SchemaMigrationRecord): Promise<void> {
		try {
			await this.collection().insertOne({
				_id: entry.id,
				appliedAt: entry.appliedAt,
				checksum: entry.checksum
			});
		} catch (err) {
			if (!isDuplicateKey(err)) throw err;
		}
	}

	async reset(): Promise<void> {
		await this.collection().deleteMany({});
	}
}

function isDuplicateKey(err: unknown): boolean {
	return (
		typeof err === 'object' &&
		err !== null &&
		'code' in err &&
		(err as { code: unknown }).code === 11000
	);
}
