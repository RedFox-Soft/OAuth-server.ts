import type { AdminAuditEntry, AdminAuditStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

// Append-only in-memory admin audit log. Entries are only ever added and read; there is no
// mutation or removal path, mirroring the interface contract.
export class AdminAuditStore implements AdminAuditStoreInstance {
	private entries: AdminAuditEntry[] = [];

	async record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry> {
		const saved: AdminAuditEntry = {
			_id: nanoid(),
			timestamp: new Date(),
			...entry
		};
		this.entries.push(saved);
		return saved;
	}

	async list(filter?: {
		targetType?: string;
		targetId?: string;
	}): Promise<AdminAuditEntry[]> {
		return this.entries.filter(
			(e) =>
				(filter?.targetType === undefined ||
					e.targetType === filter.targetType) &&
				(filter?.targetId === undefined || e.targetId === filter.targetId)
		);
	}
}
