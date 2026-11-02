import type { ConnectedAccount } from '../../connected_services/types.js';
import type { ConnectedAccountStoreInstance } from '../types.js';

/*
 * In-memory connected accounts (specs/117). The derived `_id` makes a reconnect of the same upstream account
 * a replace by key here exactly as it is a primary-key upsert on the persistent backends.
 */
export class ConnectedAccountStore implements ConnectedAccountStoreInstance {
	private records = new Map<string, ConnectedAccount>();

	async put(record: ConnectedAccount): Promise<{ created: boolean }> {
		const created = !this.records.has(record._id);
		this.records.set(record._id, structuredClone(record));
		return { created };
	}

	async find(bucketId: string, id: string): Promise<ConnectedAccount | null> {
		const record = this.records.get(id);
		return record && record.bucketId === bucketId
			? structuredClone(record)
			: null;
	}

	async listByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		return this.matching(
			(record) => record.bucketId === bucketId && record.accountId === accountId
		).map((record) => structuredClone(record));
	}

	async countByAccountAndService(
		bucketId: string,
		accountId: string,
		serviceId: string
	): Promise<number> {
		return this.matching(
			(record) =>
				record.bucketId === bucketId &&
				record.accountId === accountId &&
				record.serviceId === serviceId
		).length;
	}

	async countByService(bucketId: string, serviceId: string): Promise<number> {
		return this.matching(
			(record) => record.bucketId === bucketId && record.serviceId === serviceId
		).length;
	}

	async destroy(
		bucketId: string,
		id: string
	): Promise<ConnectedAccount | null> {
		const record = this.records.get(id);
		if (!record || record.bucketId !== bucketId) return null;
		this.records.delete(id);
		return record;
	}

	async destroyByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		return this.remove(
			(record) => record.bucketId === bucketId && record.accountId === accountId
		);
	}

	async destroyByService(
		bucketId: string,
		serviceId: string
	): Promise<ConnectedAccount[]> {
		return this.remove(
			(record) => record.bucketId === bucketId && record.serviceId === serviceId
		);
	}

	async destroyByBucket(bucketId: string): Promise<ConnectedAccount[]> {
		return this.remove((record) => record.bucketId === bucketId);
	}

	/* Test-only and pass-only: every record as stored, sealed values untouched. */
	all(): ConnectedAccount[] {
		return [...this.records.values()];
	}

	private matching(
		predicate: (record: ConnectedAccount) => boolean
	): ConnectedAccount[] {
		return [...this.records.values()].filter(predicate);
	}

	private remove(
		predicate: (record: ConnectedAccount) => boolean
	): ConnectedAccount[] {
		const removed = this.matching(predicate);
		for (const record of removed) this.records.delete(record._id);
		return removed;
	}
}
