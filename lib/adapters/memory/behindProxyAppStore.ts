import type {
	BehindProxyApp,
	BehindProxyAppPatch,
	BehindProxyAppStoreInstance,
	BehindProxyAppUsage
} from '../types.js';
import { UniqueValueTaken } from '../conflicts.js';
import { entriesOf } from '../../helpers/_/object.js';

const FIRST_TIMES = [
	'firstAskedAt',
	'firstSignInAt',
	'firstAllowedAt'
] as const;

/*
 * In-memory apps behind a proxy. The address check runs with no `await` between the read and the write, so the
 * one-address-per-bucket rule the datastores' unique index gives is observable in the default test run.
 */
export class BehindProxyAppStore implements BehindProxyAppStoreInstance {
	private records = new Map<string, BehindProxyApp>();

	private addressTaken(bucketId: string, address: string, id: string): boolean {
		for (const record of this.records.values()) {
			if (
				record._id !== id &&
				record.bucketId === bucketId &&
				record.address === address
			) {
				return true;
			}
		}
		return false;
	}

	async listByBucket(bucketId: string): Promise<BehindProxyApp[]> {
		return [...this.records.values()]
			.filter((record) => record.bucketId === bucketId)
			.map((record) => structuredClone(record));
	}

	async find(id: string): Promise<BehindProxyApp | null> {
		const record = this.records.get(id);
		return record ? structuredClone(record) : null;
	}

	async create(record: BehindProxyApp): Promise<BehindProxyApp> {
		if (
			this.records.has(record._id) ||
			this.addressTaken(record.bucketId, record.address, record._id)
		) {
			throw new UniqueValueTaken('address', record.address);
		}
		this.records.set(record._id, structuredClone(record));
		return structuredClone(record);
	}

	async update(
		id: string,
		patch: BehindProxyAppPatch
	): Promise<BehindProxyApp | null> {
		const stored = this.records.get(id);
		if (!stored) return null;
		const changed: BehindProxyApp = { ...stored, updatedAt: new Date() };
		for (const [field, value] of entriesOf(patch)) {
			if (value !== undefined) Reflect.set(changed, field, value);
		}
		if (this.addressTaken(changed.bucketId, changed.address, id)) {
			throw new UniqueValueTaken('address', changed.address);
		}
		this.records.set(id, structuredClone(changed));
		return structuredClone(changed);
	}

	async delete(id: string): Promise<void> {
		this.records.delete(id);
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const removed: string[] = [];
		for (const [id, record] of this.records) {
			if (record.bucketId === bucketId) {
				this.records.delete(id);
				removed.push(id);
			}
		}
		return removed;
	}

	async noteUsage(id: string, fields: BehindProxyAppUsage): Promise<void> {
		const stored = this.records.get(id);
		if (!stored) return;
		for (const field of FIRST_TIMES) {
			const at = fields[field];
			if (at && !stored[field]) stored[field] = new Date(at);
		}
		if (fields.lastAskedAt) stored.lastAskedAt = new Date(fields.lastAskedAt);
	}
}
