import { ApplicationConfig } from '../configs/application.js';
import {
	ATTACK_MAX_ADDRESSES,
	ATTACK_REPORT_FORMAT,
	ATTACK_REPORT_MAX_BYTES,
	ATTACK_TYPES,
	type AttackTypeName,
	type ProbeLabel
} from '../consts/attack_report_fields.js';
import { packageVersion } from '../helpers/package_version.js';
import type { HourTally } from './tally.js';

export interface ReportedAddress {
	address: string;
	counts: Partial<Record<AttackTypeName, number>>;
	probes?: ProbeLabel[];
}

export interface AttackReport {
	format: number;
	instanceId: string;
	version?: string;
	hour: string;
	addressSource: string;
	addresses: ReportedAddress[];
	omitted: number;
}

function totalOf(entry: ReportedAddress): number {
	let total = 0;
	for (const count of Object.values(entry.counts)) total += count;
	return total;
}

/*
 * One hour's report, or null when no address crossed a threshold (specs/114 research R7). A type leaves only
 * at or above its threshold, so an address whose activity stayed under every one is not in the report at all
 * (SI-004). The heaviest addresses are kept when more qualify than one report carries.
 */
export function buildAttackReport(
	hour: string,
	tally: HourTally,
	instanceId: string
): AttackReport | null {
	const qualified: ReportedAddress[] = [];
	for (const [address, entry] of tally.addresses) {
		const counts: Partial<Record<AttackTypeName, number>> = {};
		for (const type of ATTACK_TYPES) {
			const count = entry.counts[type.name];
			if (count !== undefined && count >= type.threshold) {
				counts[type.name] = count;
			}
		}
		if (Object.keys(counts).length === 0) continue;
		qualified.push(
			counts.probe === undefined
				? { address, counts }
				: { address, counts, probes: [...entry.probes].sort() }
		);
	}
	if (qualified.length === 0) return null;

	qualified.sort(
		(a, b) =>
			totalOf(b) - totalOf(a) ||
			(a.address < b.address ? -1 : a.address > b.address ? 1 : 0)
	);
	const addresses = qualified.slice(0, ATTACK_MAX_ADDRESSES);
	const version = packageVersion();
	const report: AttackReport = {
		format: ATTACK_REPORT_FORMAT,
		instanceId,
		...(version === undefined ? {} : { version }),
		hour,
		addressSource: ApplicationConfig['clientAddress.source'],
		addresses,
		omitted: qualified.length - addresses.length
	};
	// A guard rather than a path: 500 entries of the largest shape stay well under the bound.
	while (
		report.addresses.length > 1 &&
		Buffer.byteLength(JSON.stringify(report)) > ATTACK_REPORT_MAX_BYTES
	) {
		report.addresses.pop();
		report.omitted += 1;
	}
	return report;
}
