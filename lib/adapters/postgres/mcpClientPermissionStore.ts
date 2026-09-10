import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type {
	McpClientPermission,
	McpClientPermissionStoreInstance
} from '../types.js';

const DATE_FIELDS = ['createdAt', 'acknowledgedAt'] as const;

/*
 * Administrative client permissions, keyed by the permitted identifier URL or by the bare host.
 *
 * Read on every administrative MCP request, which is what makes a withdrawal land on the agent's next
 * call rather than when its token expires. Two point reads at most, both on the primary key.
 */
export class McpClientPermissionStore implements McpClientPermissionStoreInstance {
	private area: string = STORE_AREAS.mcpClientPermissions;

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

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${entry._id}, ${entry}, NULL)
		`;

		return entry;
	}

	async find(id: string): Promise<McpClientPermission | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.permissionOf(rows[0]);
	}

	async list(): Promise<McpClientPermission[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return rows
			.map((row: unknown) => this.permissionOf(row))
			.filter(
				(entry: McpClientPermission | null): entry is McpClientPermission =>
					entry !== null
			);
	}

	async update(
		id: string,
		patch: Partial<Pick<McpClientPermission, 'requireKeyProof'>>
	): Promise<McpClientPermission | null> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${patch}
			WHERE id = ${id}
			RETURNING doc
		`;
		return this.permissionOf(rows[0]);
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async findFor(identifier: string): Promise<McpClientPermission | null> {
		const handle = sql();
		const exact = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${identifier} AND doc->>'kind' = 'identifier'
		`;

		/*
		 * An exact entry wins over the host it lives on, so an operator can require key proof of one
		 * application without imposing it on every other that host publishes.
		 */
		const found = this.permissionOf(exact[0]);
		if (found) return found;

		const host = URL.parse(identifier)?.hostname;
		if (!host) return null;

		const byHost = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${host} AND doc->>'kind' = 'host'
		`;
		return this.permissionOf(byHost[0]);
	}

	private permissionOf(row: unknown): McpClientPermission | null {
		const doc = docOf<McpClientPermission>(row);
		return doc === undefined ? null : reviveDates(doc, DATE_FIELDS);
	}
}
