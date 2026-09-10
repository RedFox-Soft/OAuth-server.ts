import type {
	SchemaMigrationRecord,
	SchemaMigrationStoreInstance
} from '../types.js';

export class SchemaMigrationStore implements SchemaMigrationStoreInstance {
	private applied = new Map<string, SchemaMigrationRecord>();

	async all(): Promise<SchemaMigrationRecord[]> {
		return Array.from(this.applied.values());
	}

	/*
	 * Keyed by id, so recording the same migration twice cannot produce two records — the same property
	 * the persistent backends get from the primary key rather than from care at the call site.
	 */
	async record(entry: SchemaMigrationRecord): Promise<void> {
		this.applied.set(entry.id, entry);
	}

	async reset(): Promise<void> {
		this.applied.clear();
	}
}
