import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { AdminAuditEntry, AdminAuditStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

// Append-only MongoDB admin audit log (collection `adminAudit`). Only inserts and reads —
// no update/delete — so the trail is immutable through this adapter.
export class AdminAuditStore implements AdminAuditStoreInstance {
	private collection = db.collection<AdminAuditEntry>(STORE_AREAS.adminAudit);

	async record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry> {
		const saved: AdminAuditEntry = {
			_id: nanoid(),
			timestamp: new Date(),
			...entry
		};
		await this.collection.insertOne(saved);
		return saved;
	}

	async list(filter?: {
		targetType?: string;
		targetId?: string;
	}): Promise<AdminAuditEntry[]> {
		const query: Record<string, unknown> = {};
		if (filter?.targetType !== undefined) query.targetType = filter.targetType;
		if (filter?.targetId !== undefined) query.targetId = filter.targetId;
		return this.collection.find(query).sort({ timestamp: 1 }).toArray();
	}
}
