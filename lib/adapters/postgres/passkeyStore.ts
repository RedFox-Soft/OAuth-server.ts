import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { Passkey, type PasskeyStoreInstance } from '../types.js';

/*
 * People's passkeys (specs/139). One credential id per project is the unique index on `(doc->>'bucketId',
 * doc->>'credentialId')` the inventory declares, so a duplicate add is a constraint violation even under a concurrent
 * write. Every conditional write is one UPDATE whose WHERE is the condition: the row lock serialises two racing
 * writers, and the second re-reads the row the first wrote and no longer matches.
 */
export class PasskeyStore implements PasskeyStoreInstance {
	private area: string = STORE_AREAS.passkeys;

	async create(record: Passkey): Promise<'created' | 'exists'> {
		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${record._id}, ${record}, NULL)
			`;
			return 'created';
		} catch (error) {
			if (isUniqueViolation(error)) return 'exists';
			throw error;
		}
	}

	async findByCredential(
		bucketId: string,
		credentialId: string
	): Promise<Passkey | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'credentialId' = ${credentialId}
		`;
		return this.recordOf(rows[0]);
	}

	async find(bucketId: string, id: string): Promise<Passkey | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
		`;
		return this.recordOf(rows[0]);
	}

	async listOf(bucketId: string, accountId: string): Promise<Passkey[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
		`;
		return this.recordsOf(rows);
	}

	async countOf(bucketId: string, accountId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS n FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
		`;
		return countOf(rows[0]);
	}

	async recordUse(
		bucketId: string,
		id: string,
		use: { counter: number; backedUp: boolean; at: Date }
	): Promise<boolean> {
		const handle = sql();
		const set = {
			counter: use.counter,
			backedUp: use.backedUp,
			lastUsedAt: use.at
		};
		/* A counter that stays at zero is a device that never counts; any other must move forward. */
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${set}::jsonb
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND NOT doc ? 'copiedAt'
				AND (
					(doc->>'counter')::bigint < ${use.counter}::bigint
					OR ((doc->>'counter')::bigint = 0 AND ${use.counter}::bigint = 0)
				)
			RETURNING id
		`;
		return rows.length === 1;
	}

	async markCopied(bucketId: string, id: string, at: Date): Promise<void> {
		const handle = sql();
		const set = { copiedAt: at };
		await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${set}::jsonb
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND NOT doc ? 'copiedAt'
		`;
	}

	async rename(
		bucketId: string,
		accountId: string,
		id: string,
		name: string | undefined
	): Promise<boolean> {
		const handle = sql();
		const rows =
			name === undefined
				? await handle`
					UPDATE ${handle(this.area)} SET doc = doc - 'name'
					WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
					RETURNING id
				`
				: await handle`
					UPDATE ${handle(this.area)} SET doc = doc || ${{ name }}::jsonb
					WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
					RETURNING id
				`;
		return rows.length === 1;
	}

	async remove(
		bucketId: string,
		accountId: string,
		id: string
	): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
			RETURNING id
		`;
		return rows.length === 1;
	}

	async removeAddedSince(
		bucketId: string,
		accountId: string,
		since: Date
	): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
				AND (doc->>'createdAt')::timestamptz >= ${since}
			RETURNING id
		`;
		return rows.length;
	}

	async removeAllOf(bucketId: string, accountId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
			RETURNING id
		`;
		return rows.length;
	}

	async removeAllIn(bucketId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING id
		`;
		return rows.length;
	}

	async spendNotMe(
		bucketId: string,
		id: string,
		digest: string,
		now: number
	): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc - 'notMe'
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
				AND doc->'notMe'->>'digest' = ${digest}
				AND (doc->'notMe'->>'exp')::numeric > ${now}
			RETURNING id
		`;
		return rows.length === 1;
	}

	async holdingIn(
		bucketId: string,
		rpId: string,
		{ full = false }: { full?: boolean } = {}
	): Promise<{ accountId: string; passkeys: number }[]> {
		const handle = sql();
		const fullOnly = full
			? handle`AND (doc->'conditional') IS DISTINCT FROM 'true'::jsonb`
			: handle``;
		const rows: unknown[] = await handle`
			SELECT doc->>'accountId' AS account, count(*)::int AS passkeys FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'rpId' = ${rpId}
				AND (doc->'copiedAt' IS NULL OR jsonb_typeof(doc->'copiedAt') = 'null')
				${fullOnly}
			GROUP BY doc->>'accountId'
		`;
		return rows.flatMap((row) =>
			typeof row === 'object' &&
			row !== null &&
			'account' in row &&
			typeof row.account === 'string' &&
			'passkeys' in row &&
			typeof row.passkeys === 'number'
				? [{ accountId: row.account, passkeys: row.passkeys }]
				: []
		);
	}

	async confirm(bucketId: string, id: string): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc - 'conditional' - 'confirm'
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
				AND doc->>'conditional' = 'true'
			RETURNING id
		`;
		return rows.length === 1;
	}

	async knownAnywhere(rpId: string, credentialId: string): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			SELECT 1 FROM ${handle(this.area)}
			WHERE doc->>'credentialId' = ${credentialId} AND doc->>'rpId' = ${rpId}
			LIMIT 1
		`;
		return rows.length > 0;
	}

	private recordOf(row: unknown): Passkey | null {
		const doc = docOf(row);
		return doc === undefined ? null : documentOf(this.area, Passkey, doc);
	}

	private recordsOf(rows: readonly unknown[]): Passkey[] {
		return rows
			.map((row) => this.recordOf(row))
			.filter((record): record is Passkey => record !== null);
	}
}

function countOf(row: unknown): number {
	return typeof row === 'object' && row !== null && 'n' in row
		? Number(row.n)
		: 0;
}
