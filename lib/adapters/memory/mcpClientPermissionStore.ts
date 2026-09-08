import type {
	McpClientPermission,
	McpClientPermissionStoreInstance
} from '../types.js';

/*
 * In-memory administrative client permissions.
 *
 * `findFor` resolves an identifier against both kinds of entry in one call, which is the whole reason
 * it exists rather than leaving callers to check the exact entry and then the host one. A caller that
 * checked only the first would silently refuse access an operator did grant — and a refusal on this
 * surface is deliberately indistinguishable from every other, so nobody would be able to tell.
 */
export class McpClientPermissionStore implements McpClientPermissionStoreInstance {
	private entries = new Map<string, McpClientPermission>();

	async create(data: {
		_id: string;
		kind: 'identifier' | 'host';
		requireKeyProof?: boolean;
		loopbackAcknowledged?: boolean;
		acknowledgedBy?: string;
	}): Promise<McpClientPermission> {
		const entry: McpClientPermission = {
			_id: data._id,
			kind: data.kind,
			requireKeyProof: data.requireKeyProof ?? false,
			loopbackAcknowledged: data.loopbackAcknowledged ?? false,
			...(data.acknowledgedBy
				? { acknowledgedBy: data.acknowledgedBy, acknowledgedAt: new Date() }
				: {}),
			createdAt: new Date()
		};
		this.entries.set(entry._id, entry);
		return entry;
	}

	async find(id: string): Promise<McpClientPermission | null> {
		return this.entries.get(id) ?? null;
	}

	async list(): Promise<McpClientPermission[]> {
		return [...this.entries.values()];
	}

	async update(
		id: string,
		patch: Partial<Pick<McpClientPermission, 'requireKeyProof'>>
	): Promise<McpClientPermission | null> {
		const entry = this.entries.get(id);
		if (!entry) return null;
		Object.assign(entry, patch);
		return entry;
	}

	async destroy(id: string): Promise<void> {
		this.entries.delete(id);
	}

	async findFor(identifier: string): Promise<McpClientPermission | null> {
		const exact = this.entries.get(identifier);
		/*
		 * An exact entry wins over the host it lives on, so an operator can require key proof of one
		 * application without imposing it on every other the host publishes.
		 */
		if (exact?.kind === 'identifier') return exact;

		const host = URL.parse(identifier)?.hostname;
		if (!host) return null;

		const byHost = this.entries.get(host);
		return byHost?.kind === 'host' ? byHost : null;
	}
}
