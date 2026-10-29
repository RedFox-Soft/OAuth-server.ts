import crypto from 'crypto';

import { sql, type Tx } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	TelemetryState,
	type TelemetryCountDeltas,
	type TelemetryStateStoreInstance
} from '../types.js';

function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

export class TelemetryStateStore implements TelemetryStateStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private stateId = derivedId('telemetryState');

	async instanceId(): Promise<string> {
		const handle = sql();
		// Insert-if-absent: a process that loses the race inserts nothing and reads the winner's value.
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${this.stateId}, ${{ instanceId: crypto.randomUUID() }}, NULL)
			ON CONFLICT (id) DO NOTHING
		`;
		const stored = await this.read();
		if (!stored) {
			throw new Error('the usage-reporting state could not be read back');
		}
		return stored.instanceId;
	}

	async claimDay(day: string): Promise<boolean> {
		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{lastClaimedDay}', to_jsonb(${day}::text))
			WHERE id = ${this.stateId}
			  AND (doc->>'lastClaimedDay' IS NULL OR doc->>'lastClaimedDay' < ${day})
			RETURNING id
		`;
		return rows.length > 0;
	}

	/*
	 * Read, add and write under a row lock rather than one jsonb expression: the deltas name a variable set
	 * of grant types, and an expression nesting one jsonb_set per grant would be unreadable for no gain.
	 * The lock is what makes concurrent flushes from several processes add up instead of overwriting.
	 */
	async addCounts(
		day: string,
		deltas: TelemetryCountDeltas,
		keepDays: readonly string[]
	): Promise<void> {
		const handle = sql();
		await handle.begin(async (tx: Tx) => {
			const rows = await tx`
				SELECT doc FROM ${tx(this.area)} WHERE id = ${this.stateId} FOR UPDATE
			`;
			const stored = docOf(rows[0]);
			if (stored === undefined) return;
			const state = documentOf(this.area, TelemetryState, stored);
			const counts = { ...(state.counts ?? {}) };
			const current = counts[day] ?? {};
			const tokens = { ...(current.tokens ?? {}) };
			for (const [name, added] of Object.entries(deltas.tokens)) {
				tokens[name] = (tokens[name] ?? 0) + added;
			}
			counts[day] = {
				tokens,
				serverErrors: (current.serverErrors ?? 0) + deltas.serverErrors
			};
			for (const kept of Object.keys(counts)) {
				if (!keepDays.includes(kept)) delete counts[kept];
			}
			await tx`
				UPDATE ${tx(this.area)}
				SET doc = doc || ${{ counts }}
				WHERE id = ${this.stateId}
			`;
		});
	}

	async recordSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		const handle = sql();
		const changes: Record<string, unknown> = { lastReport: reportJson };
		if (deliveredAt) changes.lastDeliveredAt = deliveredAt.toISOString();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = doc || ${changes}
			WHERE id = ${this.stateId}
		`;
	}

	async recordAttackSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		const handle = sql();
		const changes: Record<string, unknown> = { lastAttackReport: reportJson };
		if (deliveredAt) changes.lastAttackDeliveredAt = deliveredAt.toISOString();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = doc || ${changes}
			WHERE id = ${this.stateId}
		`;
	}

	async read(): Promise<TelemetryState | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.stateId}
		`;
		const stored = docOf(rows[0]);
		return stored === undefined
			? null
			: documentOf(this.area, TelemetryState, stored);
	}
}
