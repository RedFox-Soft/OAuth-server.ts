import crypto from 'crypto';

import type {
	TelemetryCountDeltas,
	TelemetryState,
	TelemetryStateStoreInstance
} from '../types.js';

/*
 * The in-memory usage-reporting state. Single-process by construction: every method checks and writes
 * without yielding, so the atomicity the persistent backends buy with a conditional write comes free.
 */
export class TelemetryStateStore implements TelemetryStateStoreInstance {
	private state: TelemetryState | null = null;

	async instanceId(): Promise<string> {
		if (!this.state) {
			this.state = { instanceId: crypto.randomUUID() };
		}
		return this.state.instanceId;
	}

	async claimDay(day: string): Promise<boolean> {
		const state = this.state;
		if (!state) return false;
		if (state.lastClaimedDay !== undefined && state.lastClaimedDay >= day) {
			return false;
		}
		state.lastClaimedDay = day;
		return true;
	}

	async addCounts(
		day: string,
		deltas: TelemetryCountDeltas,
		keepDays: readonly string[]
	): Promise<void> {
		const state = this.state;
		if (!state) return;
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
		state.counts = counts;
	}

	async recordSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		const state = this.state;
		if (!state) return;
		state.lastReport = reportJson;
		if (deliveredAt) state.lastDeliveredAt = deliveredAt.toISOString();
	}

	async read(): Promise<TelemetryState | null> {
		return this.state ? structuredClone(this.state) : null;
	}
}
