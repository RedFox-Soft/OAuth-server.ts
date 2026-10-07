import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import { providerKeyOf } from '../connection_keys.js';
import {
	ProvisioningConnection,
	type DeprovisioningHold,
	type NewProvisioningConnection,
	type ProvisioningConnectionPatch,
	type ProvisioningConnectionStoreInstance
} from '../types.js';

/*
 * Provisioning connections. The unique indexes on `doc->>'providerKey'` and `doc->>'staticTokenDigest'`
 * enforce uniqueness, not a read-then-write check — the same absence of `ON CONFLICT` as every other
 * store here, because a refused write is the outcome the route maps to a conflict.
 */
export class ProvisioningConnectionStore implements ProvisioningConnectionStoreInstance {
	private area: string = STORE_AREAS.provisioningConnections;

	async create(
		data: NewProvisioningConnection
	): Promise<ProvisioningConnection> {
		const now = new Date();
		const connection: ProvisioningConnection = {
			...data,
			providerKey: providerKeyOf(data.bucketId, data.providerId),
			createdAt: now,
			updatedAt: now
		};
		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${connection._id}, ${connection}, NULL)
			`;
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			throw (await this.takenBy(connection._id, connection)) ?? error;
		}
		return connection;
	}

	async find(id: string): Promise<ProvisioningConnection | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.connectionOf(rows[0]);
	}

	async listByBucket(bucketId: string): Promise<ProvisioningConnection[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
		`;
		return this.connectionsOf(rows);
	}

	async findByProvider(
		bucketId: string,
		providerId: string
	): Promise<ProvisioningConnection | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'providerKey' = ${providerKeyOf(bucketId, providerId)}
		`;
		return this.connectionOf(rows[0]);
	}

	async findByStaticTokenDigest(
		digest: string
	): Promise<ProvisioningConnection | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'staticTokenDigest' = ${digest}
		`;
		return this.connectionOf(rows[0]);
	}

	/*
	 * Removals are subtracted before the merge, as in the user store: `doc || patch` cannot drop a key, so
	 * revoking a static token through a merge alone would keep its digest — and the revoked token — alive.
	 */
	async update(
		id: string,
		patch: ProvisioningConnectionPatch
	): Promise<ProvisioningConnection | null> {
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const remove: string[] = [];
		for (const [field, value] of Object.entries(patch)) {
			if (value === undefined) remove.push(field);
			else set[field] = value;
		}
		const handle = sql();
		try {
			const rows = await handle`
				UPDATE ${handle(this.area)}
				SET doc = (doc - ${handle.array(remove, 'text')}) || ${set}
				WHERE id = ${id}
				RETURNING doc
			`;
			return this.connectionOf(rows[0]);
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			throw (await this.takenBy(id, set)) ?? error;
		}
	}

	async touch(id: string, at: Date): Promise<void> {
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${{ lastUsedAt: at }}
			WHERE id = ${id}
		`;
	}

	/* Tested by type rather than key presence, so a stored JSON null reads as "not held" as absence does. */
	async holdIfFree(id: string, hold: DeprovisioningHold): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = doc || ${{ hold, updatedAt: new Date() }}
			WHERE id = ${id} AND jsonb_typeof(doc->'hold') IS DISTINCT FROM 'object'
			RETURNING id
		`;
		return rows.length === 1;
	}

	async releaseHold(id: string): Promise<ProvisioningConnection | null> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = ((doc - 'hold') || ${{ updatedAt: new Date() }})
				|| jsonb_build_object('tallyEpoch', COALESCE((doc->>'tallyEpoch')::int, 0) + 1)
			WHERE id = ${id} AND jsonb_typeof(doc->'hold') = 'object'
			RETURNING doc
		`;
		return this.connectionOf(rows[0]);
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.map((row: { id: string }) => row.id);
	}

	/*
	 * Which unique key a refused write collided on. Read back rather than parsed from the constraint name,
	 * because index names are a provisioning detail that may be hashed (provision.ts `indexName`).
	 */
	private async takenBy(
		id: string,
		written: { providerKey?: unknown; staticTokenDigest?: unknown }
	): Promise<UniqueValueTaken | null> {
		const handle = sql();
		if (typeof written.providerKey === 'string') {
			const rows = await handle`
				SELECT 1 FROM ${handle(this.area)}
				WHERE doc->>'providerKey' = ${written.providerKey} AND id <> ${id} LIMIT 1
			`;
			if (rows.length) return new UniqueValueTaken('provider', 'providerKey');
		}
		if (typeof written.staticTokenDigest === 'string') {
			const rows = await handle`
				SELECT 1 FROM ${handle(this.area)}
				WHERE doc->>'staticTokenDigest' = ${written.staticTokenDigest} AND id <> ${id} LIMIT 1
			`;
			if (rows.length) return new UniqueValueTaken('staticToken', 'digest');
		}
		return null;
	}

	private connectionOf(row: unknown): ProvisioningConnection | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, ProvisioningConnection, doc);
	}

	private connectionsOf(rows: unknown[]): ProvisioningConnection[] {
		return rows
			.map((row) => this.connectionOf(row))
			.filter((c): c is ProvisioningConnection => c !== null);
	}
}
