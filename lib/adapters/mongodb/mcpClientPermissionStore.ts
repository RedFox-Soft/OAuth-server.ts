import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	McpClientPermission,
	McpClientPermissionStoreInstance
} from '../types.js';

/*
 * Administrative client permissions, keyed by the permitted identifier URL or by the bare host.
 *
 * Read on every administrative MCP request, which is what makes a withdrawal land on the agent's next
 * call rather than when its token expires. Two point reads at most, both on the primary key.
 */
export class McpClientPermissionStore implements McpClientPermissionStoreInstance {
	private collection = db.collection<McpClientPermission>(
		STORE_AREAS.mcpClientPermissions
	);

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
		await this.collection.insertOne(entry);
		return entry;
	}

	async find(id: string): Promise<McpClientPermission | null> {
		return this.collection.findOne({ _id: id });
	}

	async list(): Promise<McpClientPermission[]> {
		return this.collection.find().toArray();
	}

	async update(
		id: string,
		patch: Partial<Pick<McpClientPermission, 'requireKeyProof'>>
	): Promise<McpClientPermission | null> {
		const result = await this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: patch },
			{ returnDocument: 'after' }
		);
		return result ?? null;
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async findFor(identifier: string): Promise<McpClientPermission | null> {
		const exact = await this.collection.findOne({
			_id: identifier,
			kind: 'identifier'
		});
		/*
		 * An exact entry wins over the host it lives on, so an operator can require key proof of one
		 * application without imposing it on every other that host publishes.
		 */
		if (exact) return exact;

		const host = URL.parse(identifier)?.hostname;
		if (!host) return null;

		return this.collection.findOne({ _id: host, kind: 'host' });
	}
}
