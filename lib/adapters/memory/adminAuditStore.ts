import type {
	AdminAuditEntry,
	AdminAuditPage,
	AdminAuditQuery,
	AdminAuditStoreInstance
} from '../types.js';
import {
	compareAuditEntries,
	matchesAuditQuery,
	normalizeAuditPaging,
	withAuditDefaults
} from '../../helpers/admin_audit_query.js';
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
		// Copied out, like list() below: a caller holding a live reference into the trail could edit
		// what the trail says, which is the one thing an append-only store must make impossible.
		return { ...saved };
	}

	async list(query: AdminAuditQuery = {}): Promise<AdminAuditPage> {
		const matched = this.entries.filter((entry) =>
			matchesAuditQuery(entry, query)
		);
		const { limit, offset } = normalizeAuditPaging(query);

		return {
			// Sorted on a copy: sorting `matched` would be harmless, but sorting the backing array in
			// place would destroy insertion order, the only record of what actually happened first.
			entries: [...matched]
				.sort(compareAuditEntries)
				.slice(offset, offset + limit)
				.map((entry) => withAuditDefaults(entry)),
			total: matched.length
		};
	}
}
