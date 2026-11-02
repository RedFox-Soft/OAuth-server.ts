import type {
	ConnectedAccount,
	ConnectedAccountBreak
} from '../../connected_services/types.js';
import type {
	ConnectedAccountStoreInstance,
	KeepAliveDue,
	RefreshedTokens
} from '../types.js';

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

	async claimRefresh(
		bucketId: string,
		id: string,
		holder: string,
		now: number,
		until: number
	): Promise<ConnectedAccount | null> {
		const record = this.owned(bucketId, id);
		if (!record) return null;
		if (record.refreshLease && record.refreshLease.until > now) return null;
		record.refreshLease = { holder, until };
		return structuredClone(record);
	}

	async finishRefresh(
		bucketId: string,
		id: string,
		holder: string,
		patch: RefreshedTokens
	): Promise<boolean> {
		const record = this.owned(bucketId, id);
		if (!record || record.refreshLease?.holder !== holder) return false;
		const { refreshToken, ...rest } = patch;
		Object.assign(record, rest, refreshToken ? { refreshToken } : {});
		if (patch.accessTokenExpiresAt === undefined)
			delete record.accessTokenExpiresAt;
		delete record.refreshLease;
		return true;
	}

	async releaseRefresh(
		bucketId: string,
		id: string,
		holder: string
	): Promise<void> {
		const record = this.owned(bucketId, id);
		if (record?.refreshLease?.holder === holder) delete record.refreshLease;
	}

	async markBroken(
		bucketId: string,
		id: string,
		reason: ConnectedAccountBreak,
		at: number
	): Promise<{ first: boolean }> {
		const record = this.owned(bucketId, id);
		if (!record || record.broken) return { first: false };
		record.broken = { reason, at, notified: true };
		delete record.refreshLease;
		return { first: true };
	}

	async noteUse(
		bucketId: string,
		id: string,
		clientId: string,
		at: number
	): Promise<void> {
		const record = this.owned(bucketId, id);
		if (!record) return;
		const entry = record.usedBy?.find((item) => item.clientId === clientId);
		if (entry) entry.at = at;
		else (record.usedBy ??= []).push({ clientId, at });
	}

	async listKeepAliveDue(due: KeepAliveDue): Promise<ConnectedAccount[]> {
		return this.matching(
			(record) =>
				record.refreshToken !== undefined &&
				record.broken === undefined &&
				((record.refreshedAt ?? 0) < due.staleBefore ||
					(record.refreshTokenExpiresAt !== undefined &&
						record.refreshTokenExpiresAt < due.expiringBefore)) &&
				(record.usedBy ?? []).some((use) => use.at >= due.usedSince)
		)
			.slice(0, due.limit)
			.map((record) => structuredClone(record));
	}

	/* Test-only and pass-only: every record as stored, sealed values untouched. */
	all(): ConnectedAccount[] {
		return [...this.records.values()];
	}

	private owned(bucketId: string, id: string): ConnectedAccount | undefined {
		const record = this.records.get(id);
		return record && record.bucketId === bucketId ? record : undefined;
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
