import { entriesOf } from '../../helpers/_/object.js';
import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import { providerKeyOf } from '../connection_keys.js';
import {
	ProvisioningConnection,
	type CredentialSlot,
	type DeprovisioningHold,
	type HeldConnection,
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

	/* The hold test `holdIfFree` and `releaseHold` use: an object, not merely a present key. */
	async bucketsHolding(): Promise<string[]> {
		const handle = sql();
		const rows = await handle<{ bucket: string }[]>`
			SELECT DISTINCT doc->>'bucketId' AS bucket FROM ${handle(this.area)}
			WHERE jsonb_typeof(doc->'hold') = 'object'
		`;
		return rows.map((row) => row.bucket);
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

	/* The expression the inventory's index on `previousStaticToken.digest` is built over, so the planner uses it. */
	async findByPreviousStaticTokenDigest(
		digest: string
	): Promise<ProvisioningConnection | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE (doc->'previousStaticToken'->>'digest') = ${digest}
		`;
		return this.connectionOf(rows[0]);
	}

	/* The same hold test as `bucketsHolding`, so the count and the bucket marks cannot disagree. */
	async listHeld(): Promise<HeldConnection[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE jsonb_typeof(doc->'hold') = 'object'
		`;
		return this.connectionsOf(rows).flatMap((connection) =>
			connection.hold
				? [
						{
							_id: connection._id,
							bucketId: connection.bucketId,
							displayName: connection.displayName,
							hold: connection.hold,
							...(connection.tallyEpoch !== undefined
								? { tallyEpoch: connection.tallyEpoch }
								: {})
						}
					]
				: []
		);
	}

	/*
	 * One conditional statement each, written with `jsonb_set` so nothing else in the document is rewritten:
	 * a request's bookkeeping must not race an administrator's replacement of the credential.
	 */
	async noteCredentialUse(
		id: string,
		slot: CredentialSlot,
		which: 'current' | 'previous',
		at: Date
	): Promise<void> {
		const handle = sql();
		/*
		 * Through `to_jsonb(text)`: a string parameter cast straight to jsonb is sent JSON-encoded by the driver,
		 * so a pre-stringified value would land as a string holding quotes — found against a real server.
		 */
		const stamp = at.toISOString();
		if (which === 'previous') {
			const field =
				slot === 'secret' ? 'previousSecret' : 'previousStaticToken';
			await handle`
				UPDATE ${handle(this.area)}
				SET doc = jsonb_set(doc, ${`{${field},lastUsedAt}`}::text[], to_jsonb(${stamp}::text))
				WHERE id = ${id} AND jsonb_typeof(doc->${field}::text) = 'object'
			`;
			return;
		}
		if (slot === 'secret') {
			await handle`
				UPDATE ${handle(this.area)}
				SET doc = jsonb_set(doc, '{oauthCredential,firstUsedAt}', to_jsonb(${stamp}::text))
				WHERE id = ${id}
					AND doc->'oauthCredential'->>'kind' = 'secret'
					AND jsonb_typeof(doc->'oauthCredential'->'firstUsedAt') IS DISTINCT FROM 'string'
			`;
			return;
		}
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{staticTokenFirstUsedAt}', to_jsonb(${stamp}::text))
			WHERE id = ${id}
				AND jsonb_typeof(doc->'staticTokenDigest') = 'string'
				AND jsonb_typeof(doc->'staticTokenFirstUsedAt') IS DISTINCT FROM 'string'
		`;
	}

	async retirePrevious(
		id: string,
		slot: CredentialSlot,
		digest: string
	): Promise<boolean> {
		const field = slot === 'secret' ? 'previousSecret' : 'previousStaticToken';
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = (doc - ${field}::text) || ${{ updatedAt: new Date() }}
			WHERE id = ${id} AND doc->${field}::text->>'digest' = ${digest}
			RETURNING id
		`;
		return rows.length === 1;
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
		for (const [field, value] of entriesOf(patch)) {
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
		const rows = await handle<{ id: string }[]>`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.map((row) => row.id);
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
