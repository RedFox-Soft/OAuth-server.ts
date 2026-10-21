import type {
	OutsideAuthorizationServer,
	OutsideAuthorizationServerStoreInstance
} from '../types.js';
import { UniqueValueTaken } from '../conflicts.js';

/*
 * In-memory outside authorization server connections. `create` refuses a duplicate rather than overwriting,
 * so the one-issuer-per-project rule the datastores' primary key gives is observable in the default test run.
 */
export class OutsideAuthorizationServerStore implements OutsideAuthorizationServerStoreInstance {
	private records = new Map<string, OutsideAuthorizationServer>();

	async create(
		record: OutsideAuthorizationServer
	): Promise<OutsideAuthorizationServer> {
		if (this.records.has(record._id)) {
			throw new UniqueValueTaken('outside authorization server', record.issuer);
		}
		this.records.set(record._id, structuredClone(record));
		return structuredClone(record);
	}

	async find(id: string): Promise<OutsideAuthorizationServer | null> {
		const record = this.records.get(id);
		return record ? structuredClone(record) : null;
	}

	async listByBucket(bucketId: string): Promise<OutsideAuthorizationServer[]> {
		return [...this.records.values()]
			.filter((record) => record.bucketId === bucketId)
			.map((record) => structuredClone(record));
	}

	async replace(record: OutsideAuthorizationServer): Promise<void> {
		if (this.records.has(record._id)) {
			this.records.set(record._id, structuredClone(record));
		}
	}

	async destroy(id: string): Promise<void> {
		this.records.delete(id);
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		let removed = 0;
		for (const [id, record] of this.records) {
			if (record.bucketId === bucketId) {
				this.records.delete(id);
				removed += 1;
			}
		}
		return removed;
	}
}
