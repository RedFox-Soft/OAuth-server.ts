import { ApplicationConfig } from '../configs/application.js';
import { selectBackend } from '../adapters/selectBackend.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import { EXAMPLE_ATTACK_REPORT } from '../consts/attack_report_fields.js';
import type { OffReason } from '../telemetry/status.js';

/*
 * The setting, then the backend, as for usage reporting (lib/telemetry/status.ts): an in-memory instance never
 * reports, because lib/index.ts does not start its timer, and the operator is told so.
 */
export function attackReportsState(): {
	enabled: boolean;
	offBecause?: OffReason;
} {
	if (!ApplicationConfig['attackReports.enabled']) {
		return { enabled: false, offBecause: 'setting' };
	}
	if (selectBackend(process.env) === 'memory') {
		return { enabled: false, offBecause: 'no-datastore' };
	}
	return { enabled: true };
}

export interface AttackReportsStatus {
	enabled: boolean;
	offBecause?: OffReason;
	setting: boolean;
	lastDeliveredAt: string | null;
	report: unknown;
	reportIsPreview: boolean;
}

/*
 * What the console card and the agent read (specs/114, FR-022, FR-024): the state and its reason, the last
 * delivery, and the last report exactly as it left, or before the first one an example with no real address.
 */
export async function attackReportsStatus(): Promise<AttackReportsStatus> {
	const stored = await getTelemetryStateStore().read();
	const state = attackReportsState();
	const sent = stored?.lastAttackReport;
	return {
		enabled: state.enabled,
		...(state.offBecause === undefined ? {} : { offBecause: state.offBecause }),
		setting: ApplicationConfig['attackReports.enabled'],
		lastDeliveredAt: stored?.lastAttackDeliveredAt ?? null,
		report:
			sent === undefined
				? EXAMPLE_ATTACK_REPORT
				: (JSON.parse(sent) as unknown),
		reportIsPreview: sent === undefined
	};
}
