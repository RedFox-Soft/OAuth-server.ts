import { ApplicationConfig } from '../configs/application.js';
import { selectBackend } from '../adapters/selectBackend.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import { now } from './clock.js';
import { buildReport } from './report.js';
import { nextSlotAfter } from './slot.js';

export type OffReason = 'setting' | 'no-datastore';

/*
 * Whether a report pass may send: the console setting, and nothing else. There is deliberately no
 * environment switch (owner, 2026-10-28): a setting lives in the database where an operator and an agent
 * can see and change it, and a second, invisible place to turn it off is one more thing to explain.
 *
 * The missing datastore is deliberately not here either. The test suite runs on the in-memory backend and
 * must be able to run passes; an in-memory instance is kept from reporting where its timer would start
 * (lib/index.ts), and the status below tells the operator so.
 */
export function reportingAllowed(): boolean {
	return ApplicationConfig['telemetry.enabled'];
}

/* What the operator is told: the setting, and whether this instance can report at all. */
export function reportingState(): { enabled: boolean; offBecause?: OffReason } {
	if (!reportingAllowed()) return { enabled: false, offBecause: 'setting' };
	if (selectBackend(process.env) === 'memory') {
		return { enabled: false, offBecause: 'no-datastore' };
	}
	return { enabled: true };
}

export interface TelemetryStatus {
	enabled: boolean;
	offBecause?: OffReason;
	setting: boolean;
	instanceId: string;
	lastDeliveredAt: string | null;
	report: unknown;
	reportIsPreview: boolean;
	nextReportAfter: string | null;
}

/*
 * What the console card and the agent read (specs/113, FR-019): the state and its reason, the identifier,
 * the last delivery, and the report itself — the one last sent, byte for byte, or before any was sent the
 * one that would be. Reading it creates the identifier if none exists yet, so what is shown is what the
 * first report will carry.
 */
export async function telemetryStatus(
	at: Date = now()
): Promise<TelemetryStatus> {
	const store = getTelemetryStateStore();
	const instanceId = await store.instanceId();
	const stored = await store.read();
	const state = reportingState();
	const sent = stored?.lastReport;
	return {
		enabled: state.enabled,
		...(state.offBecause === undefined ? {} : { offBecause: state.offBecause }),
		setting: ApplicationConfig['telemetry.enabled'],
		instanceId,
		lastDeliveredAt: stored?.lastDeliveredAt ?? null,
		report:
			sent === undefined
				? await buildReport(at, instanceId)
				: (JSON.parse(sent) as unknown),
		reportIsPreview: sent === undefined,
		nextReportAfter: state.enabled
			? nextSlotAfter(instanceId, at).toISOString()
			: null
	};
}
