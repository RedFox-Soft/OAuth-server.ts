import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	ConnectedAccount,
	type ConnectedAccountBreak
} from '../../connected_services/types.js';
import type {
	ConnectedAccountStoreInstance,
	KeepAliveDue,
	RefreshedTokens
} from '../types.js';

/*
 * Connected accounts (specs/117). `ON CONFLICT (id)` on the derived id replaces the document whole, as the
 * MongoDB store's upserting `replaceOne` does; `xmax = 0` on the returned row is PostgreSQL's own answer to
 * whether the row was inserted rather than updated.
 */
export class ConnectedAccountStore implements ConnectedAccountStoreInstance {
	private area: string = STORE_AREAS.connectedAccounts;

	async put(record: ConnectedAccount): Promise<{ created: boolean }> {
		const handle = sql();
		const rows = await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${record._id}, ${record}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
			RETURNING (xmax = 0) AS inserted
		`;
		const first: unknown = rows[0];
		return {
			created:
				typeof first === 'object' &&
				first !== null &&
				'inserted' in first &&
				first.inserted === true
		};
	}

	async find(bucketId: string, id: string): Promise<ConnectedAccount | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
		`;
		return this.recordOf(rows[0]);
	}

	async listByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
		`;
		return this.recordsOf(rows);
	}

	async countByAccountAndService(
		bucketId: string,
		accountId: string,
		serviceId: string
	): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS n FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId}
				AND doc->>'accountId' = ${accountId}
				AND doc->>'serviceId' = ${serviceId}
		`;
		return countOf(rows[0]);
	}

	async countByService(bucketId: string, serviceId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS n FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'serviceId' = ${serviceId}
		`;
		return countOf(rows[0]);
	}

	async destroy(
		bucketId: string,
		id: string
	): Promise<ConnectedAccount | null> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
			RETURNING doc
		`;
		return this.recordOf(rows[0]);
	}

	async destroyByAccount(
		bucketId: string,
		accountId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'accountId' = ${accountId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	async destroyByService(
		bucketId: string,
		serviceId: string
	): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'serviceId' = ${serviceId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	async destroyByBucket(bucketId: string): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'bucketId' = ${bucketId}
			RETURNING doc
		`;
		return this.recordsOf(rows);
	}

	async claimRefresh(
		bucketId: string,
		id: string,
		holder: string,
		now: number,
		until: number
	): Promise<ConnectedAccount | null> {
		const handle = sql();
		const lease = { holder, until };
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{refreshLease}', ${lease}::jsonb)
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
				AND (NOT doc ? 'refreshLease' OR (doc->'refreshLease'->>'until')::numeric <= ${now})
			RETURNING doc
		`;
		return this.recordOf(rows[0]);
	}

	async finishRefresh(
		bucketId: string,
		id: string,
		holder: string,
		patch: RefreshedTokens
	): Promise<boolean> {
		const { refreshToken, accessTokenExpiresAt, ...rest } = patch;
		const set = {
			...rest,
			...(refreshToken ? { refreshToken } : {}),
			...(accessTokenExpiresAt !== undefined ? { accessTokenExpiresAt } : {})
		};
		const dropped =
			accessTokenExpiresAt === undefined
				? ['refreshLease', 'accessTokenExpiresAt']
				: ['refreshLease'];
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = (doc || ${set}::jsonb) - ${handle.array(dropped, 'text')}
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
				AND doc->'refreshLease'->>'holder' = ${holder}
			RETURNING id
		`;
		return rows.length === 1;
	}

	async releaseRefresh(
		bucketId: string,
		id: string,
		holder: string
	): Promise<void> {
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)} SET doc = doc - 'refreshLease'
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
				AND doc->'refreshLease'->>'holder' = ${holder}
		`;
	}

	async markBroken(
		bucketId: string,
		id: string,
		reason: ConnectedAccountBreak,
		at: number
	): Promise<{ first: boolean }> {
		const handle = sql();
		const broken = { reason, at, notified: true };
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc - 'refreshLease', '{broken}', ${broken}::jsonb)
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId} AND NOT doc ? 'broken'
			RETURNING id
		`;
		return { first: rows.length === 1 };
	}

	/*
	 * One statement that rewrites the list, keeping the other agents' entries and replacing this one's. Two calls
	 * for one record serialise on the row lock and the later wins, which is the newer use either way.
	 */
	async noteUse(
		bucketId: string,
		id: string,
		clientId: string,
		at: number
	): Promise<void> {
		const handle = sql();
		const entry = { clientId, at };
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(
				doc,
				'{usedBy}',
				COALESCE(
					(SELECT jsonb_agg(item) FROM jsonb_array_elements(COALESCE(doc->'usedBy', '[]'::jsonb)) AS item
						WHERE item->>'clientId' <> ${clientId}),
					'[]'::jsonb
				) || jsonb_build_array(${entry}::jsonb)
			)
			WHERE id = ${id} AND doc->>'bucketId' = ${bucketId}
		`;
	}

	/* An account connected before `refreshedAt` existed counts as due, as on the other backends. */
	async listKeepAliveDue(due: KeepAliveDue): Promise<ConnectedAccount[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc ? 'refreshToken' AND NOT doc ? 'broken'
				AND (
					COALESCE((doc->>'refreshedAt')::numeric, 0) < ${due.staleBefore}
					OR (doc->>'refreshTokenExpiresAt')::numeric < ${due.expiringBefore}
				)
				AND EXISTS (
					SELECT 1 FROM jsonb_array_elements(COALESCE(doc->'usedBy', '[]'::jsonb)) AS item
					WHERE (item->>'at')::numeric >= ${due.usedSince}
				)
			LIMIT ${due.limit}
		`;
		return this.recordsOf(rows);
	}

	private recordOf(row: unknown): ConnectedAccount | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, ConnectedAccount, doc);
	}

	private recordsOf(rows: readonly unknown[]): ConnectedAccount[] {
		return rows
			.map((row) => this.recordOf(row))
			.filter((record): record is ConnectedAccount => record !== null);
	}
}

function countOf(row: unknown): number {
	return typeof row === 'object' && row !== null && 'n' in row
		? Number(row.n)
		: 0;
}
