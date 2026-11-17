import crypto from 'crypto';

import type {
	LookupFigures,
	LookupKey,
	Registration,
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

	async recordAttackSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		const state = this.state;
		if (!state) return;
		state.lastAttackReport = reportJson;
		if (deliveredAt) state.lastAttackDeliveredAt = deliveredAt.toISOString();
	}

	async raiseAttackerListBuiltAt(builtAt: string): Promise<void> {
		const state = this.state;
		if (!state) return;
		if (
			state.attackerListBuiltAt === undefined ||
			state.attackerListBuiltAt < builtAt
		) {
			state.attackerListBuiltAt = builtAt;
		}
	}

	async raiseNetworkFactsBuiltAt(builtAt: string): Promise<void> {
		const state = this.state;
		if (!state) return;
		if (
			state.networkFactsBuiltAt === undefined ||
			state.networkFactsBuiltAt < builtAt
		) {
			state.networkFactsBuiltAt = builtAt;
		}
	}

	async claimRegistrationDay(day: string): Promise<boolean> {
		const state = this.state;
		if (!state) return false;
		const claimed = state.registration?.lastClaimedDay;
		if (claimed !== undefined && claimed >= day) return false;
		state.registration = { ...(state.registration ?? {}), lastClaimedDay: day };
		return true;
	}

	async updateRegistration(
		changes: Partial<Registration>,
		clear: readonly (keyof Registration)[] = []
	): Promise<void> {
		const state = this.state;
		if (!state) return;
		const registration: Partial<Registration> = {
			...(state.registration ?? {})
		};
		for (const member of clear) delete registration[member];
		for (const [member, value] of Object.entries(changes)) {
			Reflect.set(registration, member, value);
		}
		state.registration = registration;
	}

	async setLookupKey(value: LookupKey | { droppedAt: string }): Promise<void> {
		const state = this.state;
		if (!state) return;
		if ('receivedAt' in value) {
			state.lookupKey = { ...value };
		} else if (state.lookupKey) {
			state.lookupKey = { ...state.lookupKey, droppedAt: value.droppedAt };
		}
	}

	async recordLookups(figures: LookupFigures): Promise<void> {
		const state = this.state;
		if (!state) return;
		const kept =
			figures.exhaustedDay === undefined &&
			state.lookups?.day === figures.day &&
			state.lookups.exhaustedDay !== undefined
				? { exhaustedDay: state.lookups.exhaustedDay }
				: {};
		state.lookups = { ...figures, ...kept };
	}

	async noteFirstKeyReport(at: string): Promise<void> {
		const state = this.state;
		if (!state || state.registration?.firstKeyReportAt !== undefined) return;
		state.registration = {
			...(state.registration ?? {}),
			firstKeyReportAt: at
		};
	}

	async read(): Promise<TelemetryState | null> {
		return this.state ? structuredClone(this.state) : null;
	}
}
